    # -------- Push to Postman via MCP (FULL server) ----------
    mcp = PostmanMCP()

    ws = mcp.get_workspaces() or {}
    all_ws = ws.get("workspaces") or []
    # FIX: correct attribute name is workspace_name
    workspace = next((w for w in all_ws if w.get("name") == args.workspace_name), None)
    if not workspace:
        raise RuntimeError(
            f"Workspace '{args.workspace_name}' not found via MCP. "
            f"Available: {[w.get('name') for w in all_ws]}"
        )
    workspace_id = workspace["id"]

    # 2) upsert environment
    mcp.upsert_environment(workspace_id, args.env_name, build_env_vars())

    # 3) create or update collection by name
    cols = mcp.get_collections(workspace_id) or {}
    existing = next((c for c in (cols.get("collections") or []) if c.get("name") == args.collection), None)

    if existing:
        mcp.update_collection(existing["id"], coll)
        print(f"[agent] Updated collection in Postman (id={existing['id']})")
    else:
        mcp.create_collection(workspace_id, coll)
        # pull again to print id
        cols2 = mcp.get_collections(workspace_id) or {}
        newc = next((c for c in (cols2.get("collections") or []) if c.get("name") == args.collection), None)
        print(f"[agent] Created collection in Postman (id={newc.get('id') if newc else 'unknown'})")
