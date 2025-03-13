# RP-Analyzer
Analyse the implementation and circumvention of the referrer policy. 

To utilise this module, you have two options:
1. **Implementation of the RP:** To analyse the data for implementation, execute all notebooks in the [01_extractor](/01_extractor/) folder. Upon completion, proceed to the [implementation](/03_analyzer/0301_implement/) section.
2. **Circumvention of the RP:** To analyse the circumvention of the RP, execute [request_extractor](/01_extractor/request_extractor.ipynb), followed by [Leak detector](/02_processor/0201_leak_detect.ipynb) and [circumvention detector](/02_processor/0202_circum_detect.ipynb) (consecutively). Subsequently, execute all notebooks in the [circumvention](/03_analyzer/0302_circum/) section.


## Environment
We utilised our campus server to execute this repository. Our campus server specifications include 132GB of RAM and 32 CPU cores. 

## Dataset

Our dataset is still in the process of obtaining a DOI from the [Radboud Data Repository](https://data.ru.nl). For this artefact review, we share this dataset on OneDrive as it is the only option suggested by Radboud University ([link](https://zenodo.org/records/8318561) page 39). You can find the dataset in this [OneDrive](https://radbouduniversiteit-my.sharepoint.com/:f:/r/personal/luqman_zagi_ru_nl/Documents/RP%20Dataset?csf=1&web=1&e=VtoNyS)



