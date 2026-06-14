from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient
from langmem import create_manage_memory_tool, create_search_memory_tool
from src.prompts.prompt_loader import load_prompt
from src.swarm_integrity.handoff_gate import governed_handoff_tools_for
from src.utils.llm.config_manager import get_current_llm
from src.utils.memory import get_store 
from langchain_anthropic import ChatAnthropic
from src.utils.mcp.mcp_loader import load_mcp_tools

async def make_initaccess_agent():
    llm = get_current_llm()
    
    # None 체크 추가 (주석 해제 권장)
    if llm is None:
        llm = ChatAnthropic(model_name="claude-3-5-sonnet-latest", temperature=0, timeout=60, stop=None)
        print("Warning: Using default LLM model (Claude 3.5 Sonnet)")
    
    # 중앙 집중식 store 사용
    store = get_store()
    
    mcp_tools = await load_mcp_tools(agent_name=["initial_access"])

    # Governed handoffs: every transfer passes the ShadowAuditor (role/strip/audit) first.
    swarm_tools = governed_handoff_tools_for("Initial_Access")

    mem_tools = [
        create_manage_memory_tool(namespace=("memories",)),
        create_search_memory_tool(namespace=("memories",))
    ]

    tools = mcp_tools + swarm_tools + mem_tools

    agent = create_react_agent(
        model=llm,  # 🔥 매개변수 이름 명시
        tools=tools,
        store=store,
        name="Initial_Access",
        prompt=load_prompt("initial_access", "swarm"),
    )
    return agent