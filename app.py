from flask import Flask, request, render_template
import numpy as np
import warnings
import pickle
from convert import convertion
from ssl_checker import get_certificate_info, parse_certificate_details, format_certificate_data
from urllib.parse import urlparse
from feature import FeatureExtraction

warnings.filterwarnings("ignore")

app = Flask(__name__)

# Load ML model
with open("newmodel.pkl", "rb") as file:
    gbc = pickle.load(file)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/result", methods=["POST", "GET"])
def predict():
    if request.method == "POST":
        url = request.form["name"]
        obj = FeatureExtraction(url)
        all_features_list = obj.getFeaturesList()
        https_score = obj.Hppts()
        has_https_scheme = https_score == 1

        # ML Prediction
        x = np.array(all_features_list[:30]).reshape(1, 30)
        y_pred = gbc.predict(x)[0]
        name = convertion(url, int(y_pred), has_https_scheme)

        # Feature descriptions
        feature_names = [
            "Using IP", "Long URL", "Short URL", "Symbol (@)", "Redirecting (//)",
            "Prefix-Suffix (- in domain)", "SubDomains", "HTTPS Scheme",
            "Domain Registration Length", "Favicon", "Non Standard Port",
            "HTTPS in Domain URL", "Request URL", "Anchor URL", "Links in Script Tags",
            "Server Form Handler", "Info Email", "Abnormal URL", "Website Forwarding",
            "Status Bar Customization", "Disable Right Click", "Using Popup Window",
            "Iframe Redirection", "Age of Domain", "DNS Recording", "Website Traffic",
            "Page Rank", "Google Index", "Links Pointing to Page", "Stats Report"
        ]

        features_with_names = zip(feature_names, all_features_list)

        return render_template("index.html", name=name, features=features_with_names)


@app.route("/details", methods=["POST"])
def details():
    url = request.form.get("url")
    if not url:
        return "No URL provided", 400

    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    hostname = parsed.hostname
    port = parsed.port or 443

    # Get SSL certificate details
    der_cert, cert_dict, tls_version, cipher_info = get_certificate_info(hostname, port)
    if not der_cert or not cert_dict:
        return render_template("details.html", cert_info={"error": f"Could not fetch SSL certificate for {hostname}"})

    cert_obj = parse_certificate_details(der_cert)
    cert_info = format_certificate_data(hostname, port, der_cert, cert_dict, tls_version, cipher_info, cert_obj)

    return render_template("details.html", cert_info=cert_info)


if __name__ == "__main__":
    app.run(debug=True)
