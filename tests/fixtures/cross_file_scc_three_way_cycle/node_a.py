from node_b import forward_b


def forward_a(payload):
    # 3-way cycle: forward_a -> forward_b -> forward_c -> forward_a.
    # Each edge crosses a file boundary so the SCC spans 3 namespaces.
    return forward_b(payload)
