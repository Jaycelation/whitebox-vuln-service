from fastapi import FastAPI

app = FastAPI()


@app.get("/files")
def read_file(path: str):
    with open(path) as handle:  # EXPECT path-traversal route param
        return handle.read()
