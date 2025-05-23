# Referrer-Policy-Analyzer
This repository contains the code we used to analyze data collected by the [Referrer-Policy-Crawler](https://github.com/referrer-policy-pets-25/Referrer-Policy-Crawler) for our PETS'25 paper titled "Referrer Policy: Implementation and Circumvention."

This code represents only the part highlighted with a red rectangle from our full research.

![Referrer Policy Analyzer](/method_analyzer.png)

To utilise this module, you have two options:
1. **Implementation of the Referrer Policy:** To analyze implementation data, execute all notebooks in the [01_extractor](/01_extractor/) folder. Upon completion, proceed to the [implementation](/03_analyzer/0301_implement/) section.
2. **Circumvention of the Referrer Policy:** To analyze the circumvention data, first execute [request_extractor](/01_extractor/request_extractor.ipynb), followed by [Leak detector](/02_processor/0201_leak_detect.ipynb) and [circumvention detector](/02_processor/0202_circum_detect.ipynb) in sequence. Then, run all notebooks in the [circumvention](/03_analyzer/0302_circum/) section.


## Environment
We utilised our campus server to execute this repository. Our campus server specifications include 132GB of RAM and 32 CPU cores. 

## Dataset

Our dataset is still in the process of obtaining a DOI from the [Radboud Data Repository](https://data.ru.nl/collections/ru/icis/pets-25_dsc_073). 
