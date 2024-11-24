from django.http import JsonResponse
from django.template.response import TemplateResponse

def formatted_response(request, data, template_name=None, status_code=200):
    """
    Return an appropriate response based on the request's accepted format.

    Args:
        request: The DRF request object.
        data: The data to include in the response.
        template_name: The name of the template to render (for HTML responses).
        status_code: The HTTP status code for the response.

    Returns:
        Response: A DRF Response object.
    """
    data["error_code"] = status_code
    data["error_title"] = "Session Server Error"
    if template_name and request.headers.get("Accept", "").startswith("text/html"):
        response = TemplateResponse(request, template_name, data, status=status_code)
        response.render()
    else:
        response = JsonResponse(data, status=status_code)
    
    return response