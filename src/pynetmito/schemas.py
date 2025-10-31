from datetime import datetime, timedelta
import hashlib
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Set, Union
from dateutil import parser
import re

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


TIME_PATTERN = re.compile(r"([+-]\d{2}):(\d{2}):(\d{2})$")


def parse_rust_time_dateutil(time_str: str):
    processed = TIME_PATTERN.sub(r"\1\2", time_str)

    try:
        return parser.parse(processed)
    except parser.ParserError as e:
        raise ValueError(f"Fail to parse: {time_str}") from e


def _format_timezone_offset(offset_seconds: int) -> str:
    abs_offset = abs(offset_seconds)
    hours = abs_offset // 3600
    minutes = (abs_offset % 3600) // 60
    seconds = abs_offset % 60

    sign = "+" if offset_seconds >= 0 else "-"
    return f"{sign}{hours:02d}:{minutes:02d}:{seconds:02d}"


def serialize_to_rust_time(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("Invalid datetime object: tzinfo is None")

    date_part = dt.strftime("%Y-%m-%d")
    time_part = dt.strftime("%H:%M:%S")

    microseconds = f"{dt.microsecond:06d}"

    utc_offset = dt.utcoffset()
    if utc_offset is None:
        raise ValueError("Invalid datetime object: utcoffset is None")
    offset_seconds = int(utc_offset.total_seconds())
    timezone_str = _format_timezone_offset(offset_seconds)

    return f"{date_part} {time_part}.{microseconds} {timezone_str}"


def parse_human_timespan(value: Union[str, int, float, timedelta]) -> timedelta:
    if isinstance(value, timedelta):
        return value

    if isinstance(value, (int, float)):
        return timedelta(seconds=value)

    if isinstance(value, str):
        value = value.strip().lower()

        units = {
            "s": 1,
            "sec": 1,
            "second": 1,
            "seconds": 1,
            "m": 60,
            "min": 60,
            "minute": 60,
            "minutes": 60,
            "h": 3600,
            "hr": 3600,
            "hour": 3600,
            "hours": 3600,
            "d": 86400,
            "day": 86400,
            "days": 86400,
        }

        pattern = r"(\d+(?:\.\d+)?)\s*([a-z]+)"
        matches = re.findall(pattern, value)

        if matches:
            total_seconds = 0
            for number, unit in matches:
                if unit in units:
                    total_seconds += float(number) * units[unit]
                else:
                    raise ValueError(f"Unknown unit: '{unit}'")
            return timedelta(seconds=total_seconds)

        try:
            return timedelta(seconds=float(value))
        except ValueError:
            raise ValueError(f"Fail to parse: '{value}'")


def serialize_to_human_timespan(td: timedelta) -> str:
    total_seconds = int(td.total_seconds())

    if total_seconds == 0:
        return "0s"

    if total_seconds < 0:
        return "-" + serialize_to_human_timespan(timedelta(seconds=-total_seconds))

    days = total_seconds // 86400
    remaining = total_seconds % 86400
    hours = remaining // 3600
    remaining = remaining % 3600
    minutes = remaining // 60
    seconds = remaining % 60

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if seconds > 0:
        parts.append(f"{seconds}s")

    return "".join(parts)


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


class UserState(str, Enum):
    ACTIVE = "Active"
    LOCKED = "Locked"
    DELETED = "Deleted"


class GroupState(str, Enum):
    ACTIVE = "Active"
    LOCKED = "Locked"
    DELETED = "Deleted"


class WorkerState(str, Enum):
    NORMAL = "Normal"
    GRACEFUL_SHUTDOWN = "GracefulShutdown"


class WorkerShutdownOp(str, Enum):
    GRACEFUL = "Graceful"
    FORCE = "Force"


class UserGroupRole(str, Enum):
    READ = "Read"
    WRITE = "Write"
    ADMIN = "Admin"


class GroupWorkerRole(str, Enum):
    READ = "Read"
    WRITE = "Write"
    ADMIN = "Admin"


class TaskResultMessage(str, Enum):
    FETCH_RESOURCE_TIMEOUT = "FetchResourceTimeout"
    EXEC_TIMEOUT = "ExecTimeout"
    UPLOAD_RESULT_TIMEOUT = "UploadResultTimeout"
    RESOURCE_NOT_FOUND = "ResourceNotFound"
    RESOURCE_FORBIDDEN = "ResourceForbidden"
    WATCH_TIMEOUT = "WatchTimeout"
    USER_CANCELLATION = "UserCancellation"
    SUBMIT_NEW_TASK_FAILED = "SubmitNewTaskFailed"


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
    def ser_model(self) -> Dict[str, Any]:
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

    @field_serializer("creator_usernames")
    def serialize_creator_usernames(self, creator_usernames: Optional[Set[str]]):
        return list(creator_usernames) if creator_usernames else None

    @field_validator("creator_usernames", mode="before")
    @classmethod
    def deserialize_creator_usernames(cls, creator_usernames: Optional[list[str]]):
        return set(creator_usernames) if creator_usernames else None

    @field_serializer("tags")
    def serialize_tags(self, tags: Optional[Set[str]]):
        return list(tags) if tags else None

    @field_validator("tags", mode="before")
    @classmethod
    def deserialize_tags(cls, tags: Optional[list[str]]):
        return set(tags) if tags else None

    @field_serializer("labels")
    def serialize_labels(self, labels: Optional[Set[str]]):
        return list(labels) if labels else None

    @field_validator("labels", mode="before")
    @classmethod
    def deserialize_labels(cls, labels: Optional[list[str]]):
        return set(labels) if labels else None

    @field_serializer("states")
    def serialize_states(self, states: Optional[Set[TaskState]]):
        return list(states) if states else None

    @field_validator("states", mode="before")
    @classmethod
    def deserialize_states(cls, states: Optional[list[TaskState]]):
        return set(states) if states else None


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
    created_at: datetime
    updated_at: datetime
    state: TaskState
    timeout: int
    priority: int
    spec: dict
    result: Optional[dict] = Field(default=None)
    upstream_task_uuid: Optional[UUID4] = Field(default=None)
    downstream_task_uuid: Optional[UUID4] = Field(default=None)

    @field_validator("created_at", mode="before")
    @classmethod
    def deserialize_created_at(cls, created_at: str):
        return parse_rust_time_dateutil(created_at)

    @field_validator("updated_at", mode="before")
    @classmethod
    def deserialize_updated_at(cls, updated_at: str):
        return parse_rust_time_dateutil(updated_at)

    @field_serializer("created_at")
    def serialize_created_at(self, created_at: datetime):
        return serialize_to_rust_time(created_at)

    @field_serializer("updated_at")
    def serialize_updated_at(self, updated_at: datetime):
        return serialize_to_rust_time(updated_at)


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
    created_at: datetime
    updated_at: datetime
    state: TaskState
    timeout: int
    priority: int
    spec: TaskSpec
    result: Optional[TaskResultSpec] = Field(default=None)
    upstream_task_uuid: Optional[UUID4] = Field(default=None)
    downstream_task_uuid: Optional[UUID4] = Field(default=None)

    @field_validator("created_at", mode="before")
    @classmethod
    def deserialize_created_at(cls, created_at: str):
        return parse_rust_time_dateutil(created_at)

    @field_validator("updated_at", mode="before")
    @classmethod
    def deserialize_updated_at(cls, updated_at: str):
        return parse_rust_time_dateutil(updated_at)

    @field_serializer("created_at")
    def serialize_created_at(self, created_at: datetime):
        return serialize_to_rust_time(created_at)

    @field_serializer("updated_at")
    def serialize_updated_at(self, updated_at: datetime):
        return serialize_to_rust_time(updated_at)


class TasksQueryResp(BaseAPIModel):
    count: NonNegativeInt
    tasks: list[TaskQueryInfo]
    group_name: str


class TasksCancelByFilterReq(BaseAPIModel):
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

    @field_serializer("creator_usernames")
    def serialize_creator_usernames(self, creator_usernames: Optional[Set[str]]):
        return list(creator_usernames) if creator_usernames else None

    @field_validator("creator_usernames", mode="before")
    @classmethod
    def deserialize_creator_usernames(cls, creator_usernames: Optional[list[str]]):
        return set(creator_usernames) if creator_usernames else None

    @field_serializer("tags")
    def serialize_tags(self, tags: Optional[Set[str]]):
        return list(tags) if tags else None

    @field_validator("tags", mode="before")
    @classmethod
    def deserialize_tags(cls, tags: Optional[list[str]]):
        return set(tags) if tags else None

    @field_serializer("labels")
    def serialize_labels(self, labels: Optional[Set[str]]):
        return list(labels) if labels else None

    @field_validator("labels", mode="before")
    @classmethod
    def deserialize_labels(cls, labels: Optional[list[str]]):
        return set(labels) if labels else None

    @field_serializer("states")
    def serialize_states(self, states: Optional[Set[TaskState]]):
        return list(states) if states else None

    @field_validator("states", mode="before")
    @classmethod
    def deserialize_states(cls, states: Optional[list[TaskState]]):
        return set(states) if states else None


class TasksCancelByFilterResp(BaseAPIModel):
    cancelled_count: NonNegativeInt
    group_name: str


class TasksCancelByUuidsReq(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
    )
    uuids: list[UUID4]


class TasksCancelByUuidsResp(BaseAPIModel):
    cancelled_count: NonNegativeInt
    failed_uuids: list[UUID4]


class ArtifactQueryResp(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        use_enum_values=True,
    )
    content_type: ArtifactContentType
    size: int
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", mode="before")
    @classmethod
    def deserialize_created_at(cls, created_at: str):
        return parse_rust_time_dateutil(created_at)

    @field_validator("updated_at", mode="before")
    @classmethod
    def deserialize_updated_at(cls, updated_at: str):
        return parse_rust_time_dateutil(updated_at)

    @field_serializer("created_at")
    def serialize_created_at(self, created_at: datetime):
        return serialize_to_rust_time(created_at)

    @field_serializer("updated_at")
    def serialize_updated_at(self, updated_at: datetime):
        return serialize_to_rust_time(updated_at)


class TaskQueryResp(BaseAPIModel):
    info: ParsedTaskQueryInfo
    artifacts: list[ArtifactQueryResp]


class SubmitTaskReq(BaseAPIModel):
    group_name: str
    tags: Set[str] = Field(default=set())
    labels: Set[str] = Field(default=set())
    timeout: timedelta = Field(default=timedelta(minutes=10))
    priority: int = Field(default=0)
    task_spec: TaskSpec

    @field_serializer("tags")
    def serialize_tags(self, tags: Set[str]):
        return list(tags)

    @field_validator("tags", mode="before")
    @classmethod
    def deserialize_tags(cls, tags: list[str]):
        return set(tags)

    @field_serializer("labels")
    def serialize_labels(self, labels: Set[str]):
        return list(labels)

    @field_validator("labels", mode="before")
    @classmethod
    def deserialize_labels(cls, labels: list[str]):
        return set(labels)

    @field_serializer("timeout")
    def serialize_timeout(self, timeout: timedelta):
        return serialize_to_human_timespan(timeout)

    @field_validator("timeout", mode="before")
    @classmethod
    def deserialize_timeout(cls, timeout: str):
        return parse_human_timespan(timeout)


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
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", mode="before")
    @classmethod
    def deserialize_created_at(cls, created_at: str):
        return parse_rust_time_dateutil(created_at)

    @field_validator("updated_at", mode="before")
    @classmethod
    def deserialize_updated_at(cls, updated_at: str):
        return parse_rust_time_dateutil(updated_at)

    @field_serializer("created_at")
    def serialize_created_at(self, created_at: datetime):
        return serialize_to_rust_time(created_at)

    @field_serializer("updated_at")
    def serialize_updated_at(self, updated_at: datetime):
        return serialize_to_rust_time(updated_at)


class CreateUserReq(BaseAPIModel):
    username: str
    md5_password: conlist(NonNegativeInt, min_length=16, max_length=16)
    admin: bool = Field(default=False)


class UserChangePasswordReq(BaseAPIModel):
    old_md5_password: conlist(NonNegativeInt, min_length=16, max_length=16)
    new_md5_password: conlist(NonNegativeInt, min_length=16, max_length=16)


class UserChangePasswordResp(BaseAPIModel):
    token: str


class AdminChangePasswordReq(BaseAPIModel):
    new_md5_password: conlist(NonNegativeInt, min_length=16, max_length=16)


class CreateGroupReq(BaseAPIModel):
    group_name: str


class ChangeGroupStorageQuotaReq(BaseAPIModel):
    storage_quota: str


class GroupStorageQuotaResp(BaseAPIModel):
    storage_quota: int


class ChangeUserGroupQuota(BaseAPIModel):
    group_quota: str


class UserGroupQuotaResp(BaseAPIModel):
    group_quota: int


class WorkerQueryInfo(BaseAPIModel):
    worker_id: UUID4
    creator_username: str
    tags: list[str]
    labels: list[str]
    created_at: datetime
    updated_at: datetime
    state: WorkerState
    last_heartbeat: datetime
    assigned_task_id: Optional[UUID4] = Field(default=None)

    @field_validator("created_at", mode="before")
    @classmethod
    def deserialize_created_at(cls, created_at: str):
        return parse_rust_time_dateutil(created_at)

    @field_validator("updated_at", mode="before")
    @classmethod
    def deserialize_updated_at(cls, updated_at: str):
        return parse_rust_time_dateutil(updated_at)

    @field_validator("last_heartbeat", mode="before")
    @classmethod
    def deserialize_last_heartbeat(cls, last_heartbeat: str):
        return parse_rust_time_dateutil(last_heartbeat)

    @field_serializer("created_at")
    def serialize_created_at(self, created_at: datetime):
        return serialize_to_rust_time(created_at)

    @field_serializer("updated_at")
    def serialize_updated_at(self, updated_at: datetime):
        return serialize_to_rust_time(updated_at)

    @field_serializer("last_heartbeat")
    def serialize_last_heartbeat(self, last_heartbeat: datetime):
        return serialize_to_rust_time(last_heartbeat)


class WorkerQueryResp(BaseAPIModel):
    info: WorkerQueryInfo
    groups: Dict[str, GroupWorkerRole]


class WorkersQueryReq(BaseAPIModel):
    group_name: Optional[str] = Field(default=None)
    role: Optional[Set[GroupWorkerRole]] = Field(default=None)
    tags: Optional[Set[str]] = Field(default=None)
    labels: Optional[Set[str]] = Field(default=None)
    creator_username: Optional[str] = Field(default=None)
    count: bool = Field(default=False)

    @field_serializer("role")
    def serialize_role(self, role: Optional[Set[GroupWorkerRole]]):
        return list(role) if role else None

    @field_validator("role", mode="before")
    @classmethod
    def deserialize_role(cls, role: Optional[list[GroupWorkerRole]]):
        return set(role) if role else None

    @field_serializer("tags")
    def serialize_tags(self, tags: Optional[Set[str]]):
        return list(tags) if tags else None

    @field_validator("tags", mode="before")
    @classmethod
    def deserialize_tags(cls, tags: Optional[list[str]]):
        return set(tags) if tags else None

    @field_serializer("labels")
    def serialize_labels(self, labels: Optional[Set[str]]):
        return list(labels) if labels else None

    @field_validator("labels", mode="before")
    @classmethod
    def deserialize_labels(cls, labels: Optional[list[str]]):
        return set(labels) if labels else None


class WorkersQueryResp(BaseAPIModel):
    count: NonNegativeInt
    workers: list[WorkerQueryInfo]
    group_name: str


class WorkersShutdownByFilterReq(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        use_enum_values=True,
    )
    group_name: Optional[str] = Field(default=None)
    role: Optional[Set[GroupWorkerRole]] = Field(default=None)
    tags: Optional[Set[str]] = Field(default=None)
    labels: Optional[Set[str]] = Field(default=None)
    creator_username: Optional[str] = Field(default=None)
    op: WorkerShutdownOp

    @field_serializer("role")
    def serialize_role(self, role: Optional[Set[GroupWorkerRole]]):
        return list(role) if role else None

    @field_validator("role", mode="before")
    @classmethod
    def deserialize_role(cls, role: Optional[list[GroupWorkerRole]]):
        return set(role) if role else None

    @field_serializer("tags")
    def serialize_tags(self, tags: Optional[Set[str]]):
        return list(tags) if tags else None

    @field_validator("tags", mode="before")
    @classmethod
    def deserialize_tags(cls, tags: Optional[list[str]]):
        return set(tags) if tags else None

    @field_serializer("labels")
    def serialize_labels(self, labels: Optional[Set[str]]):
        return list(labels) if labels else None

    @field_validator("labels", mode="before")
    @classmethod
    def deserialize_labels(cls, labels: Optional[list[str]]):
        return set(labels) if labels else None


class WorkersShutdownByFilterResp(BaseAPIModel):
    shutdown_count: NonNegativeInt
    group_name: str


class WorkersShutdownByUuidsReq(BaseAPIModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        use_enum_values=True,
    )
    uuids: list[UUID4]
    op: WorkerShutdownOp


class WorkersShutdownByUuidsResp(BaseAPIModel):
    shutdown_count: NonNegativeInt
    failed_uuids: list[UUID4]


class GroupQueryInfo(BaseAPIModel):
    group_name: str
    creator_username: str
    created_at: datetime
    updated_at: datetime
    state: GroupState
    task_count: int
    storage_quota: int
    storage_used: int
    worker_count: int
    users_in_group: Optional[Dict[str, UserGroupRole]] = Field(default=None)

    @field_validator("created_at", mode="before")
    @classmethod
    def deserialize_created_at(cls, created_at: str):
        return parse_rust_time_dateutil(created_at)

    @field_validator("updated_at", mode="before")
    @classmethod
    def deserialize_updated_at(cls, updated_at: str):
        return parse_rust_time_dateutil(updated_at)

    @field_serializer("created_at")
    def serialize_created_at(self, created_at: datetime):
        return serialize_to_rust_time(created_at)

    @field_serializer("updated_at")
    def serialize_updated_at(self, updated_at: datetime):
        return serialize_to_rust_time(updated_at)


class GroupsQueryResp(BaseAPIModel):
    groups: Dict[str, UserGroupRole]


class AttachmentQueryInfo(BaseAPIModel):
    key: str
    content_type: AttachmentContentType
    size: int
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", mode="before")
    @classmethod
    def deserialize_created_at(cls, created_at: str):
        return parse_rust_time_dateutil(created_at)

    @field_validator("updated_at", mode="before")
    @classmethod
    def deserialize_updated_at(cls, updated_at: str):
        return parse_rust_time_dateutil(updated_at)

    @field_serializer("created_at")
    def serialize_created_at(self, created_at: datetime):
        return serialize_to_rust_time(created_at)

    @field_serializer("updated_at")
    def serialize_updated_at(self, updated_at: datetime):
        return serialize_to_rust_time(updated_at)


class AttachmentsQueryReq(BaseAPIModel):
    key: Optional[str] = Field(default=None)
    limit: Optional[NonNegativeInt] = Field(default=None)
    offset: Optional[NonNegativeInt] = Field(default=None)
    count: bool = Field(default=False)


class AttachmentsQueryResp(BaseAPIModel):
    count: NonNegativeInt
    attachments: list[AttachmentQueryInfo]
    group_name: str


class UpdateTaskLabelsReq(BaseAPIModel):
    labels: Set[str]

    @field_serializer("labels")
    def serialize_labels(self, labels: Set[str]):
        return list(labels)

    @field_validator("labels", mode="before")
    @classmethod
    def deserialize_labels(cls, labels: list[str]):
        return set(labels)


class ChangeTaskReq(BaseAPIModel):
    tags: Optional[Set[str]] = Field(default=None)
    timeout: Optional[timedelta] = Field(default=None)
    priority: Optional[int] = Field(default=None)
    task_spec: Optional[TaskSpec] = Field(default=None)

    @field_serializer("tags")
    def serialize_tags(self, tags: Optional[Set[str]]):
        return list(tags) if tags else None

    @field_validator("tags", mode="before")
    @classmethod
    def deserialize_tags(cls, tags: Optional[list[str]]):
        return set(tags) if tags else None

    @field_serializer("timeout")
    def serialize_timeout(self, timeout: Optional[timedelta]):
        return serialize_to_human_timespan(timeout) if timeout else None

    @field_validator("timeout", mode="before")
    @classmethod
    def deserialize_timeout(cls, timeout: Optional[str]):
        return parse_human_timespan(timeout) if timeout else None


class ReplaceWorkerTagsReq(BaseAPIModel):
    tags: Set[str]

    @field_serializer("tags")
    def serialize_tags(self, tags: Set[str]):
        return list(tags)

    @field_validator("tags", mode="before")
    @classmethod
    def deserialize_tags(cls, tags: list[str]):
        return set(tags)


class ReplaceWorkerLabelsReq(BaseAPIModel):
    labels: Set[str]

    @field_serializer("labels")
    def serialize_labels(self, labels: Set[str]):
        return list(labels)

    @field_validator("labels", mode="before")
    @classmethod
    def deserialize_labels(cls, labels: list[str]):
        return set(labels)


class UpdateGroupWorkerRoleReq(BaseAPIModel):
    relations: Dict[str, GroupWorkerRole]


class RemoveGroupWorkerRoleReq(BaseAPIModel):
    groups: Set[str]

    @field_serializer("groups")
    def serialize_groups(self, groups: Set[str]):
        return list(groups)

    @field_validator("groups", mode="before")
    @classmethod
    def deserialize_groups(cls, groups: list[str]):
        return set(groups)


class UpdateUserGroupRoleReq(BaseAPIModel):
    relations: Dict[str, UserGroupRole]


class RemoveUserGroupRoleReq(BaseAPIModel):
    users: Set[str]

    @field_serializer("users")
    def serialize_users(self, users: Set[str]):
        return list(users)

    @field_validator("users", mode="before")
    @classmethod
    def deserialize_users(cls, users: list[str]):
        return set(users)


class ShutdownReq(BaseAPIModel):
    secret: str


class RedisConnectionInfo(BaseAPIModel):
    url: Optional[str] = Field(default=None)


class ArtifactsDownloadByFilterReq(BaseAPIModel):
    """Request to batch download artifacts by filter criteria."""

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
    content_type: ArtifactContentType

    @field_serializer("creator_usernames")
    def serialize_creator_usernames(self, creator_usernames: Optional[Set[str]]):
        return list(creator_usernames) if creator_usernames else None

    @field_validator("creator_usernames", mode="before")
    @classmethod
    def deserialize_creator_usernames(cls, creator_usernames: Optional[list[str]]):
        return set(creator_usernames) if creator_usernames else None

    @field_serializer("tags")
    def serialize_tags(self, tags: Optional[Set[str]]):
        return list(tags) if tags else None

    @field_validator("tags", mode="before")
    @classmethod
    def deserialize_tags(cls, tags: Optional[list[str]]):
        return set(tags) if tags else None

    @field_serializer("labels")
    def serialize_labels(self, labels: Optional[Set[str]]):
        return list(labels) if labels else None

    @field_validator("labels", mode="before")
    @classmethod
    def deserialize_labels(cls, labels: Optional[list[str]]):
        return set(labels) if labels else None

    @field_serializer("states")
    def serialize_states(self, states: Optional[Set[TaskState]]):
        return list(states) if states else None

    @field_validator("states", mode="before")
    @classmethod
    def deserialize_states(cls, states: Optional[list[TaskState]]):
        return set(states) if states else None


class ArtifactsDownloadByUuidsReq(BaseAPIModel):
    """Request to batch download artifacts by task UUIDs."""

    uuids: list[UUID4]
    content_type: ArtifactContentType


class ArtifactDownloadItem(BaseAPIModel):
    """Single artifact download item in batch response."""

    uuid: UUID4
    url: str
    size: int


class ArtifactsDownloadListResp(BaseAPIModel):
    """Response for batch artifact download operations."""

    downloads: list[ArtifactDownloadItem]


class AttachmentsDownloadByFilterReq(BaseAPIModel):
    """Request to batch download attachments by filter criteria."""

    key: Optional[str] = Field(default=None)
    limit: Optional[NonNegativeInt] = Field(default=None)
    offset: Optional[NonNegativeInt] = Field(default=None)


class AttachmentsDownloadByKeysReq(BaseAPIModel):
    """Request to batch download attachments by keys."""

    keys: list[str]


class AttachmentDownloadItem(BaseAPIModel):
    """Single attachment download item in batch response."""

    key: str
    url: str
    size: int


class AttachmentsDownloadListResp(BaseAPIModel):
    """Response for batch attachment download operations."""

    downloads: list[AttachmentDownloadItem]
    group_name: str
