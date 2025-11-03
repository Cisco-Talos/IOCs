import os

from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate

from urlextract import URLExtract
from urllib.parse import urlparse
import tldextract

from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth

import re
import requests
import json

# Export/Set the environment variables
umbrella_key = os.environ.get('UMBRELLA_KEY')
umbrella_secret = os.environ.get('UMBRELLA_SECRET')
openai_key = os.environ.get('OPENAI_API_KEY')

UMBRELLA_AUTH_BASE='https://api.umbrella.com/auth/v2'
UMBRELLA_API_BASE='https://api.umbrella.com/investigate/v2'


# Define the function for URL address detection
def detectAndCheckURL(input_text):
    """
    Detects if the text includes a URL
    Returns 'This contains a URL.' with the domains and dispositions if a domain is found, otherwise 'No URLs found.'
    """
# Quick check if the input contains any URLs
    extractor = URLExtract()
    if extractor.has_urls(input_text):
# There are domains.
# Prepare a session token for Umbrella
        umbrella_token_data = getUmbrellaSessionToken(umbrella_key,umbrella_secret)
        access_token = umbrella_token_data.get('access_token')
        full_data_text = 'This contains a URL.'
# Review each URL in turn
        for url in extractor.gen_urls(input_text):
            parsed_url = tldextract.extract(url)
            full_domain = f"{parsed_url.subdomain}.{parsed_url.domain}.{parsed_url.suffix}"
            domain_disposition = getDomainDisposition(full_domain,access_token)
            full_data_text = full_data_text + domain_disposition
        print (f"RETURNING {full_data_text}")
        return full_data_text
# If no URLs, return.       
    else:
        return "No URLs found. "

# Query Umbrella API to get domain disposition
def getDomainDisposition(query_domain,access_token):
    endpoint = '/domains/categorization/'    
    url = f"{UMBRELLA_API_BASE}{endpoint}{query_domain}?showLabels"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json" 
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()

    domain_disposition = f"Considering {query_domain}. "
    
    domain_status = response.json()[query_domain]["status"]
    if domain_status == 1:
        domain_disposition = domain_disposition + f"The domain {query_domain} has a positive disposition. "
    elif domain_status == -1:
        domain_disposition = domain_disposition + f"The domain {query_domain} is known to be malicious. "
    elif domain_status == 0:
        domain_disposition = domain_disposition + f"The disposition of {query_domain} is unkown. "

    if domain_status == -1:
        domain_disposition = domain_disposition + f"The domain {query_domain} is known to be: "
        domain_disposition = domain_disposition + ', '.join(response.json()[query_domain]["security_categories"]) +'.'

    elif response.json()[query_domain]["content_categories"]:
        domain_disposition = domain_disposition + f"The domain {query_domain} is classified as: "
        domain_disposition = domain_disposition + ', '.join(response.json()[query_domain]["content_categories"]) +'.'

    return(domain_disposition)
            

# Get session token for Umbrella API. Requires authorised Umbrella key and key secret.
def getUmbrellaSessionToken(umbrella_key,umbrella_secret):
    endpoint = '/token'
    url = UMBRELLA_AUTH_BASE+endpoint

    auth = HTTPBasicAuth(umbrella_key, umbrella_secret)
    client = BackendApplicationClient(client_id=umbrella_key)
    oauth = OAuth2Session(client=client)
    token = oauth.fetch_token(token_url=url, auth=auth)

    return token


# Create a LangChain Tool from the function
# The description is vital for the LLM to understand when to use this tool.
domain_disposition_tool = Tool(
    name="Domain_Checker",
    func=detectAndCheckURL,
    description=(
        "Use this tool to check if the users input contains an internet domain. It takes the full user\
        query as input. If a safe domain is found, it will report that the domain has a positive disposition.\
        If a malicious domain is found, it will report that the domain is known to be malicious. If an\
        unknown domain is found, it will report that the domain has an unknown disposition. If no domain is\
        found, it will report 'No URLs found.'"
    )
)

# Define the tools available to the agent
tools = [domain_disposition_tool]

# Initialize the Large Language Model (LLM)
# We use a low temperature for more deterministic behavior in tool selection.
llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0,api_key=openai_key)


# Define the prompt for the agent
# This prompt guides the LLM on how to reason and use the available tools.
prompt = PromptTemplate.from_template("""
You are an internet safety chatbot. You have access to the following tools:

{tools}

Use the following format:

Question: Check user input for safety. You should verify if any internet domains are safe and appropriate for browsing.
Thought: you should always think about what to do and call the tools to check the disposition of a domain.
Action: the action to take, should be one of {tool_names}
Action Input: the input is supplied by the user.
Observation: Collect information about the disposition of a domain.
Thought: Known malicious domains are never safe, domains with positive disposition are usually safe. A domain with an unknown disposition might be safe if it is categorised.
Action: Provide the Final Answer.
Final Answer: If you find a domain that you don't think is safe, reply 'do not connect'. If the domain is safe or you're uncertain, say so. If there are no domains or you receive the information 'No URLs found', you must reply 'no opinion' and stop. This is the final response to human.

Begin!

Question: {input}
Thought:{agent_scratchpad}
""")

# Create the agent
# We use `create_react_agent` which makes the LLM reason step-by-step (Thought, Action, Observation).
agent = create_react_agent(llm, tools, prompt)

# Create the AgentExecutor
# This is the runtime for the agent, allowing it to execute actions.
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True, handle_parsing_errors=True)

# Test the agent with various inputs
print("--- Test Case 1: Input with a positive domain ---")
response = agent_executor.invoke({"input": "Should I browse www.cisco.com?"})
print(f"Agent Response: {response['output']}\n")

print("--- Test Case 2: Input with a malicious domain ---")
response = agent_executor.invoke({"input": "I'm going to connect to http://pivqmane.com/doc"})
print(f"Agent Response: {response['output']}\n")

print("--- Test Case 3: Input with multiple domains ---")
response = agent_executor.invoke({"input": "My network uses www.umbrella.com and test.example.com for testing."})
print(f"Agent Response: {response['output']}\n")

print("--- Test Case 4: Input without a domain ---")
response = agent_executor.invoke({"input": "Is Madrid the capital of France?"})
print(f"Agent Response: {response['output']}\n")
