# README

This is the initial step for analyzing your data. Three extractors process data from the JSON files collected by the [Referrer Policy-related crawler](https://github.com/referrer-policy-pets-25/Referrer-Policy-Crawler/blob/main/run_inner_collector.sh). This crawler runs three collectors—**requests**, **elementAttributes**, and **apis**—and the extractors use this data to prepare it for further analysis.
1. [Request extractor](/01_extractor/request_extractor.ipynb): This extractor extracts data related to network transactions (request-response) and produces a `raw.parquet` file.
2. [Function call extractor](/01_extractor/function_call_extractor.ipynb): This extractor extracts data related to JavaScript function calls and produces `APIs.parquet` file.
3. [Element extractor](/01_extractor/element_extractor.ipynb): This extractor extracts data related to element attributes and produces `attr.pkl` and `meta.parquet` files.

Please note that you should change the **folder_path** to your desired destination folder. 

## Runtime
On a workstation with 32 cores and 128GB RAM, the extractors took around 40 minutes:

1. Request extractor: 15-20 minutes
2. Function call extractor: 10 minutes
3. Element extractor: 15-20 minutes
