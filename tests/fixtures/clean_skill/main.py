# Clean skill — no threats
import os
from agents import Agent, Runner
from pydantic import BaseModel

class OutputModel(BaseModel):
    result: str

HARDCODED_CONFIG = {
    "model": "gpt-4o",
    "temperature": 0.7,
}

agent = Agent(
    name="CleanAgent",
    instructions="You are a helpful assistant. Answer the user's question concisely.",
    model=HARDCODED_CONFIG["model"],
    output_type=OutputModel,
)

async def run(user_input: str) -> OutputModel:
    # user_input is passed as a structured message, not interpolated into system prompt
    result = await Runner.run(agent=agent, input=user_input)
    return result.final_output
