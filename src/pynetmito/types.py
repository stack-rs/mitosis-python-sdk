from typing import Any, Dict
from pydantic import BaseModel, ConfigDict


class BaseAPIModel(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        # use_enum_values=True,
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(exclude_none=True, mode="json")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        return cls.model_validate(data)
