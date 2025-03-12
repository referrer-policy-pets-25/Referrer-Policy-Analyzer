# README

All of the results section that found in our study came from this folder.

Prior to executing either the [implementation section](/03_analyzer/0301_implement/) or the [circumvention section](/03_analyzer/0302_circum/), it is imperative to execute the [intersection](/03_analyzer/0300_intersection.ipynb) file. This function is essential for determining the intersection between three vantage points, allowing for a direct comparison of the results. If you choose to re-run our dataset, the [intersection file](/helpers/intersection) is already provided. 

## Implementation
Within this folder, Jupyter notebooks are primarily located within the “Implementation” subsection of the “Results” section. The primary purpose of these notebooks is to investigate the practical implementation of RP in real-world scenarios.

|File | Pre-requist | Result |
|-|-|-|
| [doc_wide](/03_analyzer/0301_implement/doc_wide.ipynb)| [request_extractor](/01_extractor/request_extractor.ipynb) & [element_extractor](/01_extractor/element_extractor.ipynb) | §4.1.1 |
| [el_specific](/03_analyzer/0301_implement/el_specific.ipynb)| [element_extractor](/01_extractor/element_extractor.ipynb) | §4.1.2 |
| [JS_call](/03_analyzer/0301_implement/JS_call.ipynb)| [function_call_extractor](/01_extractor/function_call_extractor.ipynb) | §4.2.6 |
| [req_RP](/03_analyzer/0301_implement/req_RP.ipynb)| [request_extractor](/01_extractor/request_extractor.ipynb) | §4.1.3 §4.1.4 |


## Circumvention
Within this folder, Jupyter notebooks are primarily located within the “Circumvention” subsection of the “Results” section. The primary purpose of these notebooks is to investigate the circumvention of the RP in real-world scenarios.

|File | Pre-requist | Result |
|-|-|-|
| [category](/03_analyzer/0302_circum/category.ipynb) | [circumvention detector](/02_processor/0202_circum_detect.ipynb)| §4.2.2 |
| [domain_entity](/03_analyzer/0302_circum/domain_entitiy.ipynb) |[circumvention detector](/02_processor/0202_circum_detect.ipynb)  |§4.2.1 |
| [encoding](/03_analyzer/0302_circum/encoding.ipynb) |[circumvention detector](/02_processor/0202_circum_detect.ipynb)  |§4.2.5 |
| [general](/03_analyzer/0302_circum/general.ipynb) |[circumvention detector](/02_processor/0202_circum_detect.ipynb)  |§4.2 |
| [three_vectors](/03_analyzer/0302_circum/three_vectors.ipynb) |[circumvention detector](/02_processor/0202_circum_detect.ipynb)  |§4.2.3 |
