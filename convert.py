import re
import csv

def convertion(url, prediction, has_https_scheme):
    """
    Converts URL analysis results and ML prediction into a structured format
    for frontend display, including whether the URL uses HTTPS.

    Args:
        url (str): The URL that was analyzed.
        prediction (int): The ML model's prediction (1 for safe, 0 for not safe).
        has_https_scheme (bool): True if the URL uses HTTPS, False otherwise.

    Returns:
        dict: A dictionary containing URL, main status, message, prediction score,
              and HTTPS scheme status for frontend display.
    """
    
    # Check for shortlink first
    if shortlink(url) == -1:
        return {
            "url": url,
            "status": "Not Safe",
            "message": "This URL uses a known shortener, often used in phishing.",
            "prediction_score": "0", # Assume shortener implies not safe
            "has_https_scheme": has_https_scheme # Include HTTPS status here
        }
    elif prediction == 1:
        return {
            "url": url,
            "status": "Safe",
            "message": "This website appears safe to use.",
            "prediction_score": "1",
            "has_https_scheme": has_https_scheme # Include HTTPS status here
        }
    else: # prediction is 0 or -1 (not safe)
        return {
            "url": url,
            "status": "Not Safe",
            "message": "This website has characteristics of a phishing site. Proceed with caution.",
            "prediction_score": "0",
            "has_https_scheme": has_https_scheme # Include HTTPS status here
        }

def shortlink(url):
    """
    Checks if the URL uses a known URL shortening service.
    Returns -1 if a shortener is found, 1 otherwise.
    """
    match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                      url)
    if match:
        return -1
    return 1

def find_url_in_csv(csv_file, target_url):
    """
    Searches for a target URL within a specified CSV file.
    (Currently commented out in original code, kept for context)
    """
    with open(csv_file, 'r', newline='', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            url = row[0].strip()
            if url == target_url:
                return url
    return None
