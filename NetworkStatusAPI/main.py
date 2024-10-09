import json
import random
from fastapi import FastAPI
from pydantic import BaseModel
from uvicorn import Config, Server
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "*",
    "http://localhost",
    "http://localhost:7777"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

class DataModel(BaseModel):
    IPAddress: str
    VulnerabilityID: int
    VulnerabilityName: str
    Synopsis: str
    Description: str
    SeeAlso: list
    Solution: str
    RiskFactor: str
    CVSSv3BaseScore: str
    CVSSv3TemporalScore: str
    CVSSBaseScore: str
    CVSSTemporalScore: str
    References: list
    PluginInformation: str

@app.head('/')
@app.post('/api/v1/status')
async def getStatus(data: DataModel):
    try:
        jsonData = json.load(open("types.json"))
        return { 'status': 200, 'label': random.choice(jsonData['types']) }
    except:
        return { 'status': 404, 'label': "Hiba történt a kérés során" }


if __name__ == "__main__":
    uvicorn_config = Config(app=app, host="127.0.0.1", port=7777)
    uvicorn_server = Server(uvicorn_config)
    uvicorn_server.run()