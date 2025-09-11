# Mitosis Python SDK

This is the Python client SDK to interact with the Mitosis API. It provides a convenient way to access Mitosis services and manage your resources programmatically.

See the [Mitosis documentation](https://docs.stack.rs/mitosis) and [Mitosis repository](https://github.com/stack-rs/mitosis) for more details.

## Usage

Install the package with pip

```bash
pip install pynetmito
```

Or if you are using [uv](https://docs.astral.sh/uv/), you can add it to your project with:

```bash
uv add pynetmito
```

Now let's see a simple example of how to use the SDK:

```python
from pynetmito import MitoHttpClient
coordinator_addr = "http://127.0.0.1:5000" # The coordinator address of the mitosis backend service
c = MitoHttpClient(coordinator_addr)
c.connect(user="your-user-name", password="your-password")

# Now you can use the client to submit tasks
with open("orig.txt", "w") as f:
    f.write("hello world")
c.upload_attachment(Path("orig.txt"), key="some-remote-text-file/in-object-storage/log.txt")

# Specify the task with attachment
attachment = RemoteResourceDownload(
    remote_file=RemoteResource.attachment("some-remote-text-file/in-object-storage/log.txt"), local_path=Path("test.txt")
)
task_spec = TaskSpec(args=["echo", "$MITO_RESOURCE/test.txt"], resources=[attachment], terminal_output=True)
args = SubmitTaskReq(group_name=c.username, task_spec=task_spec)
r = c.user_submit_task(args) # This will return a SubmitTaskResp object (with uuid to identify the task)
res = c.get_task_by_uuid(r.uuid) # You can use the uuid to get the task status and result
print(res)

# To download the terminal output of the task
c.download_artifact(
    r.uuid,
    content_type=ArtifactContentType.STD_LOG,
    local_path=Path("new.txt"),
)

```

## Mitosis API support table

| **Mitosis** | **pynetmito** |
| :---------: | :-----------: |
|    0.6.0    |     0.2.0     |
|    0.5.3    |     0.1.3     |
