import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]


def scan_web(target_url):

    try:

        # Send request to website
        response = requests.get(
            target_url,
            timeout=10
        )

        # Identify HTTP or HTTPS
        protocol = response.url.split(":")[0].upper()


        # Check Security Headers

        header_results = {}

        for header in SECURITY_HEADERS:

            if header in response.headers:

                header_results[header] = {
                    "status": "Present",
                    "value": response.headers[header]
                }

            else:

                header_results[header] = {
                    "status": "Missing",
                    "value": None
                }


        # Check Cookies

        cookies = []

        for cookie in response.cookies:

            cookies.append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.get_nonstandard_attr("SameSite")
            })


        # Check Server Information

        server = response.headers.get("Server")


        # Create Final Result

        result = {
            "url": target_url,
            "status_code": response.status_code,
            "protocol": protocol,
            "security_headers": header_results,
            "cookies": cookies,
            "server": server
        }

        return result


    except requests.exceptions.RequestException as error:

        return {
            "url": target_url,
            "error": str(error)
        }


# Run Scanner

if __name__ == "__main__":

    target = input("Enter website URL: ")

    result = scan_web(target)

    print("\n========== WEB SCAN RESULT ==========\n")

    print(result)
