def check_rate_limit(request):
    client_id = request.headers.get("X-Client-ID", "anonymous")
    request.state.client_id = client_id
    return True
