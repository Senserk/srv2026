FROM zricethezav/gitleaks:v8.24.2 AS gitleaks
FROM anchore/syft:v1.18.1 AS syft
FROM anchore/grype:v0.84.0 AS grype
FROM aquasec/trivy:0.58.1 AS trivy

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-18

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash build-essential ca-certificates clang clang-tools libclang-rt-18-dev llvm-18 cmake curl \
       docker.io git jq less nano python3 tree \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

COPY seed /opt/practice/seed
COPY .gitleaks.toml /opt/practice/gitleaks.toml
COPY playbook.sh /opt/practice/student-playbook.sh
COPY report-template.md /opt/practice/report-template.md
COPY verify/verify.py /opt/practice/verify.py
COPY tools/sarif_triage.py /usr/local/bin/sarif-triage
COPY lab/reset-practice /usr/local/bin/practice-reset
COPY lab/entrypoint.sh /usr/local/bin/practice-entrypoint

RUN chmod +x /usr/local/bin/sarif-triage /usr/local/bin/practice-reset /usr/local/bin/practice-entrypoint \
    /opt/practice/student-playbook.sh \
    && mkdir -p /work

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/practice-entrypoint"]
CMD ["sleep", "infinity"]
