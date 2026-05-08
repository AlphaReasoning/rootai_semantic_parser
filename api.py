"""Optional FastAPI service for parse/query/graph access."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from async_parse import scan_async
from graph_queries import GraphQueryEngine, GraphQueryError


app = FastAPI(title="RootAI Semantic Parser API", version="0.21.0")
_GRAPHS: Dict[str, Dict[str, Any]] = {}


class ParseRequest(BaseModel):
    root: str
    profile: str = "bugbounty"
    min_score: float = 4.5
    quick_mode: bool = False
    use_cache: bool = True
    enable_reachability: bool = True
    enable_auth_checks: bool = True
    only_reachable_unsanitized: bool = False
    collaborator_base: str = ""


class QueryRequest(BaseModel):
    graph_id: str
    expr: str


@app.post("/parse")
def parse_repo(request: ParseRequest) -> Dict[str, Any]:
    """Parse a repository and persist the resulting graph in memory."""
    result = scan_async(
        workspace_path=request.root,
        profile=request.profile,
        min_score=request.min_score,
        quick_mode=request.quick_mode,
        use_cache=request.use_cache,
        enable_reachability=request.enable_reachability,
        enable_auth_checks=request.enable_auth_checks,
        only_reachable_unsanitized=request.only_reachable_unsanitized,
        collaborator_base=request.collaborator_base,
    )
    graph_id = uuid.uuid4().hex
    _GRAPHS[graph_id] = result["report"]["graph"]
    return {"graph_id": graph_id, "report": result["report"]}


@app.post("/query")
def query_graph(request: QueryRequest) -> Dict[str, Any]:
    """Run a deterministic query against a stored graph."""
    graph = _GRAPHS.get(request.graph_id)
    if graph is None:
        raise HTTPException(status_code=404, detail="Unknown graph id")
    try:
        result = GraphQueryEngine(graph).execute(request.expr)
    except GraphQueryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@app.get("/graph/{graph_id}")
def get_graph(graph_id: str) -> Dict[str, Any]:
    """Return a stored graph payload."""
    graph = _GRAPHS.get(graph_id)
    if graph is None:
        raise HTTPException(status_code=404, detail="Unknown graph id")
    return graph
