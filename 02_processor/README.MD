# README
Prior to executing this jupyternotebook, it is needed to run the [request_extractor](/01_extractor/request_extractor.ipynb).

## Leak Detect
Adopted the Leak Detector tool from [Senol et al.](https://www.usenix.org/conference/usenixsecurity22/presentation/senol) This tool incorporates various encoding and hashing techniques, such as Base64 and URL encoding, during its search for leaks in request details. To identify potential leaks, we specifically searched for page URL components within third-party request details. Utilising Python’s urllib.urlparse function, we parsed the URL into its constituent elements, including the hostname, path, parameters, query, and fragments. These components were subsequently employed as search terms to detect URL leaks within the request URL, POST body, and Referer header.


## Circumvention Detector
Not all URL transmissions to third parties constitute RP circumvention. If the RP permits, it can disclose the complete URL (excluding fragments) to third parties. To detect circumvention, we compare the CDP-provided referrerPolicy property of each third-party request with the transmitted URL components. We classify the results into three categories:
1) circumvention (full URL): if it involves the full URL or origin combined with path or query parameters when the RP disallows sharing;
2) circumvention (partial): if it sends path or query parameters when the RP disallows or;
3) safe: if no circumvention is detected.
A challenge was false positives due to short paths and query parameters. To mitigate this, we only detect circumvention for paths and queries longer than ten characters.


## Environment
We utilised our campus server to execute this processor. Our campus server specifications include 132GB of RAM and 32 CPU cores. 

Estimated time:
1. leak_detect: 2 hours
2. circum_detect: 15 minutes. 
