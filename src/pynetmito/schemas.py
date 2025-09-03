import hashlib
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Set, Union

from pydantic import (
    UUID4,
    ConfigDict,
    Field,
    NonNegativeInt,
    conlist,
    model_serializer,
    model_validator,
    field_serializer,
    field_validator,
)

from pynetmito import BaseAPIModel


class UserLoginArgs(BaseAPIModel):
    username: str
    password: str
    retain: bool = Field(default=False)

    def to_req(self) -> "UserLoginReq":
        md5_password = hashlib.md5(self.password.encode()).digest()
        md5_password = [x for x in md5_password]
        return UserLoginReq(
            username=self.username,
            md5_password=md5_password,
            retain=self.retain,
        )


class UserLoginReq(BaseAPIModel):
    username: str
    md5_password: conlist(NonNegativeInt, min_length=16, max_length=16)
    retain: bool = Field(default=False)


class UserLoginResp(BaseAPIModel):
    token: str


class TaskState(str, Enum):
    PENDING = "Pending"
    READY = "Ready"
    RUNNING = "Running"
    FINISHED = "Finished"
    CANCELLED = "Cancelled"
    UNKNOWN = "Unknown"


class ArtifactContentType(str, Enum):
    RESULT = "result"
    EXEC_LOG = "exec-log"
    STD_LOG = "std-log"


class AttachmentContentType(str, Enum):
    NOT_SET = "NotSet"


class TaskExecState(str, Enum):
    WORKER_EXITED = "WorkerExited"
    FETCH_RESOURCE = "FetchResource"
    FETCH_RESOURCE_FINISHED = "FetchResourceFinished"
    FETCH_RESOURCE_ERROR = "FetchResourceError"
    FETCH_RESOURCE_TIMEOUT = "FetchResourceTimeout"
    FETCH_RESOURCE_NOT_FOUND = "FetchResourceNotFound"
    FETCH_RESOURCE_FORBIDDEN = "FetchResourceForbidden"
    WATCH = "Watch"
    WATCH_FINISHED = "WatchFinished"
    WATCH_TIMEOUT = "WatchTimeout"
    EXEC_PENDING = "ExecPending"
    EXEC_SPAWNED = "ExecSpawned"
    EXEC_FINISHED = "ExecFinished"
    EXEC_TIMEOUT = "ExecTimeout"
    UPLOAD_RESULT = "UploadResult"
    UPLOAD_FINISHED_RESULT = "UploadFinishedResult"
    UPLOAD_CANCELLED_RESULT = "UploadCancelledResult"
    UPLOAD_RESULT_FINISHED = "UploadResultFinished"
    UPLOAD_RESULT_TIMEOUT = "UploadResultTimeout"
    TASK_COMMITTED = "TaskCommitted"
    UNKNOWN = "Unknown"


class TaskResultMessage(str, Enum):
    FETCH_RESOURCE_TIMEOUT = "FetchResourceTimeout"
    EXEC_TIMEOUT = "ExecTimeout"
    UPLOAD_RESULT_TIMEOUT = "UploadResultTimeout"
    RESOURCE_NOT_FOUND = "ResourceNotFound"
    RESOURCE_FORBIDDEN = "ResourceForbidden"
    WATCH_TIMEOUT = "WatchTimeout"
    USER_CANCELLATION = "UserCancellation"


class RemoteResourceArtifact(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        use_enum_values=True,
    )
    uuid: UUID4
    content_type: ArtifactContentType


class RemoteResourceAttachment(BaseAPIModel):
    key: str


class RemoteResource(BaseAPIModel):
    """
    Tagged union (Rust enum) for RemoteResource.
    Uses discriminated union pattern for proper serialization.
    """

    model_config = ConfigDict(use_enum_values=True)

    root: Union[RemoteResourceArtifact, RemoteResourceAttachment]

    @classmethod
    def artifact(
        cls, uuid: UUID4, content_type: ArtifactContentType
    ) -> "RemoteResource":
        """Create an Artifact variant."""
        return cls(root=RemoteResourceArtifact(uuid=uuid, content_type=content_type))

    @classmethod
    def attachment(cls, key: str) -> "RemoteResource":
        """Create an Attachment variant."""
        return cls(root=RemoteResourceAttachment(key=key))

    @model_serializer
    def ser_model(self, **kwargs):
        """Override to match Rust's enum serialization format."""
        match self.root:
            case RemoteResourceArtifact():
                return {"Artifact": self.root.model_dump(**kwargs)}
            case RemoteResourceAttachment():
                return {"Attachment": self.root.model_dump(**kwargs)}

    @model_validator(mode="before")
    @classmethod
    def deser_model(cls, obj):
        """Custom validation to handle Rust enum format and internal construction."""
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, dict):
            # Handle internal Python construction: {"root": RemoteResourceArtifact/Attachment}
            if "root" in obj:
                root_obj = obj["root"]
                if isinstance(
                    root_obj, (RemoteResourceAttachment, RemoteResourceArtifact)
                ):
                    return obj  # Pass through as-is for normal Pydantic validation

            # Handle Rust enum deserialization format: {"Artifact": {...}} or {"Attachment": {...}}
            if "Artifact" in obj:
                return {"root": RemoteResourceArtifact(**obj["Artifact"])}
            elif "Attachment" in obj:
                return {"root": RemoteResourceAttachment(**obj["Attachment"])}

        raise ValueError("Invalid data for RemoteResource")


class RemoteResourceDownload(BaseAPIModel):
    """
    Model for RemoteResourceDownload struct.
    Handles serialization/deserialization compatible with Rust serde.
    """

    remote_file: RemoteResource
    local_path: Path

    @model_serializer
    def ser_model(self, **kwargs) -> Dict[str, Any]:
        data = {
            "remote_file": self.remote_file.ser_model(),
            "local_path": str(self.local_path),
        }
        return data

    @model_validator(mode="before")
    @classmethod
    def deser_model(cls, data: Any):
        if not isinstance(data, dict):
            raise ValueError("Invalid data for RemoteResourceDownload")
        if "remote_file" in data and isinstance(data["remote_file"], dict):
            data["remote_file"] = RemoteResource.model_validate(data["remote_file"])
        if "local_path" in data and isinstance(data["local_path"], str):
            data["local_path"] = Path(data["local_path"])
        return data


class RemoteResourceDownloadResp(BaseAPIModel):
    url: str
    size: int


class TaskSpec(BaseAPIModel):
    args: list[str]
    envs: Dict[str, str] = Field(default={})
    resources: list[RemoteResourceDownload] = Field(default=[])
    terminal_output: bool = Field(default=False)
    watch: Optional[tuple[UUID4, TaskExecState]] = Field(default=None)


class TaskResultSpec(BaseAPIModel):
    exit_status: int
    msg: Optional[TaskResultMessage] = Field(default=None)


class TasksQueryReq(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        use_enum_values=True,
    )
    creator_usernames: Optional[Set[str]] = Field(default=None)
    group_name: Optional[str] = Field(default=None)
    tags: Optional[Set[str]] = Field(default=None)
    labels: Optional[Set[str]] = Field(default=None)
    states: Optional[Set[TaskState]] = Field(default=None)
    exit_status: Optional[str] = Field(default=None)
    priority: Optional[str] = Field(default=None)
    limit: Optional[NonNegativeInt] = Field(default=None)
    offset: Optional[NonNegativeInt] = Field(default=None)
    count: bool = Field(default=False)


class TaskQueryInfo(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        use_enum_values=True,
    )
    uuid: UUID4
    creator_username: str
    group_name: str
    task_id: int
    tags: list[str]
    labels: list[str]
    created_at: str
    updated_at: str
    state: TaskState
    timeout: int
    priority: int
    spec: dict
    result: Optional[dict] = Field(default=None)


class ParsedTaskQueryInfo(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        use_enum_values=True,
    )
    uuid: UUID4
    creator_username: str
    group_name: str
    task_id: int
    tags: list[str]
    labels: list[str]
    # TODO: parse
    created_at: str
    updated_at: str
    state: TaskState
    timeout: int
    priority: int
    spec: TaskSpec
    result: Optional[TaskResultSpec] = Field(default=None)


class TasksQueryResp(BaseAPIModel):
    count: NonNegativeInt
    tasks: list[TaskQueryInfo]
    group_name: str


class ArtifactQueryResp(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        use_enum_values=True,
    )
    content_type: ArtifactContentType
    size: int
    # TODO: parse
    created_at: str
    updated_at: str


class TaskQueryResp(BaseAPIModel):
    info: ParsedTaskQueryInfo
    artifacts: list[ArtifactQueryResp]


class SubmitTaskReq(BaseAPIModel):
    group_name: str
    tags: Set[str] = Field(default=set())
    labels: Set[str] = Field(default=set())
    # TODO: change to human readable format
    timeout: str = Field(default="10min")
    priority: int = Field(default=0)
    task_spec: TaskSpec

    @field_serializer("tags")
    def serialize_tags(self, tags: Set[str], _info):
        return list(tags)

    @field_validator("tags", mode="before")
    @classmethod
    def deserialize_tags(cls, tags: list[str], _info):
        return set(tags)

    @field_serializer("labels")
    def serialize_labels(self, labels: Set[str], _info):
        return list(labels)

    @field_validator("labels", mode="before")
    @classmethod
    def deserialize_labels(cls, labels: list[str], _info):
        return set(labels)


class SubmitTaskResp(BaseAPIModel):
    task_id: int
    uuid: UUID4


class UploadArtifactReq(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        use_enum_values=True,
    )
    content_type: ArtifactContentType
    content_length: NonNegativeInt


class UploadArtifactResp(BaseAPIModel):
    url: str


class UploadAttachmentReq(BaseAPIModel):
    key: str
    content_length: NonNegativeInt


class UploadAttachmentResp(BaseAPIModel):
    url: str


class AttachmentMetadata(BaseAPIModel):
    content_type: AttachmentContentType
    size: int
    # TODO: parse
    created_at: str
    updated_at: str
