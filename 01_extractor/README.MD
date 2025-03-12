# README

This is the initial step for you to analyse your data. Three extractors extract data from your JSON files.
1. [Request extractor](/01_extractor/request_extractor.ipynb): This extractor extracts data related to network transactions (request-response) and produces a raw.parquet file.
2. [Function call extractor](/01_extractor/function_call_extractor.ipynb): This extractor extracts data related to JavaScript function calls and produces APIs.parquet file.
3. [Element extractor](/01_extractor/element_extractor.ipynb): This extractor extracts data related to element attributes and produces attr.pkl and meta.parquet files.

Please note that you should change the **folder_path** to your desired destination folder. 

## Environment
We utilised our campus server to execute this extractor. Our campus server specifications include 132GB of RAM and 32 CPU cores. 

Estimated time:
1. Request extractor: 15-20 minutes
2. Function call extractor: 10 minutes
3. Element extractor: 15-20 minutes
