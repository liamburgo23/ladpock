from langchain_experimental.tools import PythonREPLTool
from langchain_community.tools import ShellTool
import anthropic

client = anthropic.Anthropic()
tools = [PythonREPLTool(), ShellTool()]
chain = build(allow_dangerous_code=True)


def run(request):
    response = client.messages.create(model=request.json["model"], max_tokens=100, system=f"Help {request.json['user']}", messages=[])
    answer = response.content[0].text
    exec(answer)
