<!-- changelog: none -->
Prepared human-only SLH wallet fault controls in a cfg(test)-only driver and
bounded Python orchestration; ordinary wallet/node runtime behavior is unchanged.
The reopen control checks the existing public `SubmissionUnknown` result after
an unavailable submission, preserving the wallet's durable uncertainty contract.
