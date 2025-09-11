import logging
from pathlib import Path
from typing import Optional

import httpx
import platformdirs
from pydantic import UUID4, AnyHttpUrl, NonNegativeInt

from pynetmito.schemas import (
    UserLoginArgs,
    UserLoginReq,
    UserLoginResp,
    TaskQueryResp,
    TasksQueryReq,
    TasksQueryResp,
    SubmitTaskReq,
    SubmitTaskResp,
    UploadArtifactReq,
    UploadArtifactResp,
    RemoteResourceDownloadResp,
    UploadAttachmentReq,
    UploadAttachmentResp,
    AttachmentMetadata,
    ArtifactContentType,
    CreateUserReq,
    UserChangePasswordReq,
    UserChangePasswordResp,
    AdminChangePasswordReq,
    CreateGroupReq,
    ChangeGroupStorageQuotaReq,
    GroupStorageQuotaResp,
    WorkerQueryResp,
    WorkersQueryReq,
    WorkersQueryResp,
    GroupQueryInfo,
    GroupsQueryResp,
    AttachmentsQueryReq,
    AttachmentsQueryResp,
    UpdateTaskLabelsReq,
    ChangeTaskReq,
    ReplaceWorkerTagsReq,
    ReplaceWorkerLabelsReq,
    UpdateGroupWorkerRoleReq,
    RemoveGroupWorkerRoleReq,
    UpdateUserGroupRoleReq,
    RemoveUserGroupRoleReq,
    ShutdownReq,
    RedisConnectionInfo,
)


def get_logger():
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    logger = logging.getLogger("pynetmito")
    logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    return logger


class MitoHttpClient:
    client: httpx.Client
    url: AnyHttpUrl
    credential: str
    credential_path: Path
    username: Optional[str]

    def __init__(self, coordinator_addr: str):
        self.http_client = httpx.Client()
        self.url = AnyHttpUrl(coordinator_addr)
        self.credential: str = ""
        self.credential_path: Path = Path()
        self.logger = get_logger()
        self.username = None

    def __del__(self):
        self.http_client.close()

    def _get_url(self, path: str, query: str | None = None) -> str:
        host = "127.0.0.1" if self.url.host is None else self.url.host
        return str(
            AnyHttpUrl.build(
                scheme=self.url.scheme,
                host=host,
                port=self.url.port,
                path=path,
                query=query,
            )
        )

    def extract_credential(
        self, user: Optional[str], lines: list[str]
    ) -> Optional[tuple[str, str]]:
        if user is not None:
            prefix = f"{user}:"
            for line in lines:
                line = line.strip()
                if line.startswith(prefix):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        username, token = parts
                        return (username, token)
            return None
        else:
            if lines:
                line = lines[0].strip()
                parts = line.split(":", 1)
                if len(parts) == 2:
                    username, token = parts
                    return (username, token)
            return None

    def modify_or_append_credential(self, cred_path: Path, username: str, token: str):
        if cred_path.exists():
            lines = []
            with open(cred_path, "r") as f:
                lines = f.readlines()
            new_lines = []
            prefix = f"{username}:"
            found = False

            for line in lines:
                if line.startswith(prefix):
                    new_lines.append(f"{username}:{token}")
                    found = True
                else:
                    new_lines.append(line.strip())

            if not found:
                new_lines.append(f"{username}:{token}")

            with open(cred_path, "w") as f:
                f.write("\n".join(new_lines))
        else:
            with open(cred_path, "w") as f:
                f.write(f"{username}:{token}")

    def connect(
        self,
        credential_path: Optional[Path] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        retain: bool = False,
    ) -> str:
        if credential_path is not None:
            cred_path = credential_path
        else:
            cred_path = Path(platformdirs.user_config_dir("mitosis") + "/credentials")
        if cred_path.exists():
            # read each line of the file
            lines = []
            with open(cred_path, "r") as f:
                lines = f.readlines()
            res = self.extract_credential(user, lines)
            if res is not None:
                username, token = res
                url = self._get_url("auth")
                headers = {"Authorization": f"Bearer {token}"}
                resp = self.http_client.get(url, headers=headers)
                if resp.status_code == 200:
                    user = resp.text
                    self.credential = token
                    self.credential_path = cred_path
                    self.username = user
                    return user
                elif resp.status_code >= 500 and resp.status_code < 600:
                    self.logger.error(resp.json())
                    raise Exception(
                        f"Failed to authenticate, status code: {resp.status_code}, error: {resp.json()}"
                    )
        if user is None or password is None:
            raise Exception(
                "No credential file found, please provide username and password to login."
            )
        else:
            args = UserLoginArgs(username=user, password=password, retain=retain)
            req = args.to_req()
            url = self._get_url("login")
            resp = self.http_client.post(url, json=req.to_dict())
            if resp.status_code == 200:
                r = UserLoginResp.model_validate(resp.json())
                token = r.token
                # create credential file and parent directory
                cred_path.parent.mkdir(parents=True, exist_ok=True)
                self.credential = token
                self.credential_path = cred_path
                self.modify_or_append_credential(cred_path, user, token)
                self.username = user
                return user
            else:
                self.logger.error(resp.text)
                raise Exception(
                    f"Failed to login, status code: {resp.status_code}, error: {resp.text}"
                )

    def user_auth(self) -> str:
        url = self._get_url("auth")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.get(url, headers=headers)
        if resp.status_code == 200:
            user = resp.text
            return user
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to authenticate, status code: {resp.status_code}, error: {resp.text}"
            )

    def user_login(self, req: UserLoginReq):
        url = self._get_url("login")
        resp = self.http_client.post(url, json=req.to_dict())
        if resp.status_code == 200:
            r = UserLoginResp.model_validate(resp.json())
            token = r.token
            self.credential = token
            if self.credential_path.exists() and self.username is not None:
                self.credential_path.parent.mkdir(parents=True, exist_ok=True)
                self.modify_or_append_credential(
                    self.credential_path, self.username, token
                )
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to login, status code: {resp.status_code}, error: {resp.text}"
            )

    def get_task_by_uuid(self, uuid: UUID4) -> TaskQueryResp:
        url = self._get_url(f"tasks/{str(uuid)}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.get(url, headers=headers)
        if resp.status_code == 200:
            r = TaskQueryResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get task {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def query_tasks_by_filter(self, req: TasksQueryReq) -> TasksQueryResp:
        url = self._get_url("tasks/query")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            r = TasksQueryResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to query tasks, status code: {resp.status_code}, error: {resp.text}"
            )

    def user_submit_task(self, req: SubmitTaskReq) -> SubmitTaskResp:
        url = self._get_url("tasks")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.model_dump())
        if resp.status_code == 200:
            r = SubmitTaskResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to submit task, status code: {resp.status_code}, error: {resp.text}"
            )

    def upload_file(self, url: str, content_length: NonNegativeInt, local_path: Path):
        with open(local_path, "rb") as f:
            resp = self.http_client.put(
                url, headers={"Content-Length": str(content_length)}, data=f
            )
            if resp.status_code != 200:
                self.logger.error(resp.text)

    def download_file(self, resp: RemoteResourceDownloadResp, local_path: Path):
        with self.http_client.stream("GET", resp.url) as r:
            r.raise_for_status()
            with open(local_path, "wb") as f:
                for chunk in r.iter_raw():
                    f.write(chunk)

    def get_upload_artifact_resp(
        self, uuid: UUID4, req: UploadArtifactReq
    ) -> UploadArtifactResp:
        url = self._get_url(f"tasks/{str(uuid)}/artifacts")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            r = UploadArtifactResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get upload artifact url for task {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def upload_artifact(
        self, local_path: Path, uuid: UUID4, content_type: ArtifactContentType
    ):
        if local_path.is_dir():
            raise Exception("local_path should be a file, not a directory")
        file_size = local_path.stat().st_size
        req = UploadArtifactReq(content_type=content_type, content_length=file_size)
        resp = self.get_upload_artifact_resp(uuid, req)
        self.upload_file(resp.url, file_size, local_path)

    def get_upload_attachment_resp(
        self, group_name: str, req: UploadAttachmentReq
    ) -> UploadAttachmentResp:
        url = self._get_url(f"groups/{group_name}/attachments")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            r = UploadAttachmentResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get upload attachment url for group {group_name}, status code: {resp.status_code}, error: {resp.text}"
            )

    def upload_attachment(
        self,
        local_path: Path,
        group_name: Optional[str] = None,
        key: Optional[str] = None,
    ):
        if local_path.is_dir():
            raise Exception("local_path should be a file, not a directory")
        if group_name is None:
            if self.username is None:
                raise Exception("group_name is not provided and username is None")
            group_name = self.username
        file_size = local_path.stat().st_size
        if key is not None:
            req = UploadAttachmentReq(key=key, content_length=file_size)
        else:
            req = UploadAttachmentReq(key=local_path.name, content_length=file_size)
        resp = self.get_upload_attachment_resp(group_name, req)
        self.upload_file(resp.url, file_size, local_path)

    def get_artifact_download_resp(
        self, uuid: UUID4, content_type: ArtifactContentType
    ) -> RemoteResourceDownloadResp:
        url = self._get_url(
            f"tasks/{str(uuid)}/download/artifacts/{content_type.value}"
        )
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.get(url, headers=headers)
        if resp.status_code == 200:
            r = RemoteResourceDownloadResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get download artifact url for task {str(uuid)} and content type {content_type.value}, status code: {resp.status_code}, error: {resp.text}"
            )

    def download_artifact(
        self,
        uuid: UUID4,
        content_type: ArtifactContentType,
        local_path: Optional[Path] = None,
    ):
        if local_path is not None and local_path.is_dir():
            raise Exception("local_path should be a file, not a directory")
        resp = self.get_artifact_download_resp(uuid, content_type)
        if local_path is None:
            local_path = Path(f"{content_type.value}.tar.gz")
        self.download_file(resp, local_path)

    def get_attachment_download_resp(
        self, group_name: str, key: str
    ) -> RemoteResourceDownloadResp:
        url = self._get_url(f"groups/{group_name}/download/attachments/{key}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.get(url, headers=headers)
        if resp.status_code == 200:
            r = RemoteResourceDownloadResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get download attachment url for group {group_name} and key {key}, status code: {resp.status_code}, error: {resp.text}"
            )

    def download_attachment(
        self,
        key: str,
        group_name: Optional[str] = None,
        local_path: Optional[Path] = None,
    ):
        if local_path is not None and local_path.is_dir():
            raise Exception("local_path should be a file, not a directory")
        if group_name is None:
            if self.username is None:
                raise Exception("group_name is not provided and username is None")
            group_name = self.username
        resp = self.get_attachment_download_resp(group_name, key)
        if local_path is None:
            local_path = Path(key)
        self.download_file(resp, local_path)

    def get_attachment(
        self, key: str, group_name: Optional[str] = None
    ) -> AttachmentMetadata:
        if group_name is None:
            if self.username is None:
                raise Exception("group_name is not provided and username is None")
            group_name = self.username
        url = self._get_url(f"groups/{group_name}/attachments/{key}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.get(url, headers=headers)
        if resp.status_code == 200:
            r = AttachmentMetadata.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get attachment meta for group {group_name} and key {key}, status code: {resp.status_code}, error: {resp.text}"
            )

    def get_redis_connection_info(self) -> RedisConnectionInfo:
        url = self._get_url("redis")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.get(url, headers=headers)
        if resp.status_code == 200:
            r = RedisConnectionInfo.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get Redis connection info, status code: {resp.status_code}, error: {resp.text}"
            )

    def user_change_password(
        self, username: str, req: UserChangePasswordReq
    ) -> UserChangePasswordResp:
        url = self._get_url(f"users/{username}/password")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            r = UserChangePasswordResp.model_validate(resp.json())
            self.credential = r.token
            if self.credential_path.exists() and self.username is not None:
                self.credential_path.parent.mkdir(parents=True, exist_ok=True)
                self.modify_or_append_credential(
                    self.credential_path, username, self.credential
                )
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to change password for user {username}, status code: {resp.status_code}, error: {resp.text}"
            )

    def admin_change_password(self, username: str, req: AdminChangePasswordReq):
        url = self._get_url(f"admin/users/{username}/password")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to change password for user {username} (admin), status code: {resp.status_code}, error: {resp.text}"
            )

    def admin_create_user(self, req: CreateUserReq):
        url = self._get_url("admin/users")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to create user, status code: {resp.status_code}, error: {resp.text}"
            )

    def admin_delete_user(self, username: str):
        url = self._get_url(f"admin/users/{username}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.delete(url, headers=headers)
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to delete user {username}, status code: {resp.status_code}, error: {resp.text}"
            )

    def admin_cancel_worker_by_uuid(self, uuid: UUID4, force: bool = False):
        if force:
            url = self._get_url(f"admin/workers/{str(uuid)}", query="op=force")
        else:
            url = self._get_url(f"admin/workers/{str(uuid)}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.delete(url, headers=headers)
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to cancel worker {str(uuid)} (admin), status code: {resp.status_code}, error: {resp.text}"
            )

    def user_create_group(self, req: CreateGroupReq):
        url = self._get_url("groups")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to create group, status code: {resp.status_code}, error: {resp.text}"
            )

    def delete_artifact(
        self, uuid: UUID4, content_type: ArtifactContentType, admin: bool = False
    ):
        if admin:
            url = self._get_url(
                f"admin/tasks/{str(uuid)}/artifacts/{content_type.value}"
            )
        else:
            url = self._get_url(f"tasks/{str(uuid)}/artifacts/{content_type.value}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.delete(url, headers=headers)
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to delete artifact for task {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def delete_attachment(self, group_name: str, key: str, admin: bool = False):
        if admin:
            url = self._get_url(f"admin/groups/{group_name}/attachments/{key}")
        else:
            url = self._get_url(f"groups/{group_name}/attachments/{key}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.delete(url, headers=headers)
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to delete attachment for group {group_name} and key {key}, status code: {resp.status_code}, error: {resp.text}"
            )

    def admin_update_group_storage_quota(
        self, group_name: str, req: ChangeGroupStorageQuotaReq
    ) -> GroupStorageQuotaResp:
        url = self._get_url(f"admin/groups/{group_name}/storage-quota")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            r = GroupStorageQuotaResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to update storage quota for group {group_name}, status code: {resp.status_code}, error: {resp.text}"
            )

    def query_attachments_by_filter(
        self, group_name: str, req: AttachmentsQueryReq
    ) -> AttachmentsQueryResp:
        url = self._get_url(f"groups/{group_name}/attachments/query")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            r = AttachmentsQueryResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to query attachments for group {group_name}, status code: {resp.status_code}, error: {resp.text}"
            )

    def get_worker_by_uuid(self, uuid: UUID4) -> WorkerQueryResp:
        url = self._get_url(f"workers/{str(uuid)}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.get(url, headers=headers)
        if resp.status_code == 200:
            r = WorkerQueryResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get worker {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def query_workers_by_filter(self, req: WorkersQueryReq) -> WorkersQueryResp:
        url = self._get_url("workers/query")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            r = WorkersQueryResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to query workers, status code: {resp.status_code}, error: {resp.text}"
            )

    def get_group_by_name(self, group_name: str) -> GroupQueryInfo:
        url = self._get_url(f"groups/{group_name}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.get(url, headers=headers)
        if resp.status_code == 200:
            r = GroupQueryInfo.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get group {group_name}, status code: {resp.status_code}, error: {resp.text}"
            )

    def get_user_groups_roles(self) -> GroupsQueryResp:
        url = self._get_url("users/groups")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.get(url, headers=headers)
        if resp.status_code == 200:
            r = GroupsQueryResp.model_validate(resp.json())
            return r
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to get user groups roles, status code: {resp.status_code}, error: {resp.text}"
            )

    def cancel_worker_by_uuid(self, uuid: UUID4, force: bool = False):
        if force:
            url = self._get_url(f"workers/{str(uuid)}", query="op=force")
        else:
            url = self._get_url(f"workers/{str(uuid)}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.delete(url, headers=headers)
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to cancel worker {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def replace_worker_tags(self, uuid: UUID4, req: ReplaceWorkerTagsReq):
        url = self._get_url(f"workers/{str(uuid)}/tags")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.put(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to replace worker tags for {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def replace_worker_labels(self, uuid: UUID4, req: ReplaceWorkerLabelsReq):
        url = self._get_url(f"workers/{str(uuid)}/labels")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.put(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to replace worker labels for {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def update_group_worker_roles(self, uuid: UUID4, req: UpdateGroupWorkerRoleReq):
        url = self._get_url(f"workers/{str(uuid)}/groups")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.put(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to update group worker roles for {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def remove_group_worker_roles(self, uuid: UUID4, req: RemoveGroupWorkerRoleReq):
        url = self._get_url(f"workers/{str(uuid)}/groups")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.delete(
            url, headers=headers, params={"groups": list(req.groups)}
        )
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to remove group worker roles for {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def cancel_task_by_uuid(self, uuid: UUID4):
        url = self._get_url(f"tasks/{str(uuid)}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.delete(url, headers=headers)
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to cancel task {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def update_task_labels(self, uuid: UUID4, req: UpdateTaskLabelsReq):
        url = self._get_url(f"tasks/{str(uuid)}/labels")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.put(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to update task labels for {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def change_task(self, uuid: UUID4, req: ChangeTaskReq):
        url = self._get_url(f"tasks/{str(uuid)}")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.put(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to change task {str(uuid)}, status code: {resp.status_code}, error: {resp.text}"
            )

    def update_user_group_roles(self, group_name: str, req: UpdateUserGroupRoleReq):
        url = self._get_url(f"groups/{group_name}/users")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.put(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to update user group roles for group {group_name}, status code: {resp.status_code}, error: {resp.text}"
            )

    def remove_user_group_roles(self, group_name: str, req: RemoveUserGroupRoleReq):
        url = self._get_url(f"groups/{group_name}/users")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.delete(
            url, headers=headers, params={"users": list(req.users)}
        )
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to remove user group roles for group {group_name}, status code: {resp.status_code}, error: {resp.text}"
            )

    def admin_shutdown_coordinator(self, req: ShutdownReq):
        url = self._get_url("admin/shutdown")
        headers = {"Authorization": f"Bearer {self.credential}"}
        resp = self.http_client.post(url, headers=headers, json=req.to_dict())
        if resp.status_code == 200:
            return
        else:
            self.logger.error(resp.text)
            raise Exception(
                f"Failed to shutdown coordinator, status code: {resp.status_code}, error: {resp.text}"
            )
