FROM python:3.12.1-slim-bullseye

ENV VIRTUAL_ENV=/srv/dac/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install system dependencies
RUN apt-get update && apt-get install -y \
curl \
git \
zip \
unzip \
jq \
build-essential \
libffi-dev \
libssl-dev \
libxml2-dev \
libxslt1-dev \
zlib1g-dev \
gcc \
bash \
&& rm -rf /var/lib/apt/lists/*

# Set working directory
RUN mkdir /srv/dac
WORKDIR "/srv/dac"

# Clone necessary repos
RUN git clone https://github.com/elastic/detection-rules.git
RUN git clone https://github.com/SigmaHQ/sigma.git
RUN git clone https://github.com/SigmaHQ/sigma-cli.git
RUN git clone https://github.com/047741/GEKO.git

# Create virtual environment and activate
RUN python3.12 -m venv .venv

#Install dependancies
RUN python3.12 -m pip install requests
RUN python3.12 -m pip install pyyaml
RUN python3.12 -m pip install toml
RUN python3.12 -m pip install urllib3
RUN python3.12 -m pip install python-dotenv

# Install Elastic detection-rules with [hunting, dev] extras, then install kibana/kql
RUN python3.12 -m pip install --upgrade pip setuptools
RUN python3.12 -m pip install ./detection-rules[hunting,dev]
RUN python3.12 -m pip install ./detection-rules/lib/kibana
RUN python3.12 -m pip install ./detection-rules/lib/kql

# Install pySigma & sigma-cli
RUN python3.12 -m pip install pySigma
RUN python3.12 -m pip install sigma-cli

#Install the elasticsearch plugin
RUN sigma plugin install elasticsearch
RUN sigma plugin install windows

#Set entrypoint to venv shell
COPY entrypoint.sh /srv/dac/entrypoint.sh
RUN chmod +x /srv/dac/entrypoint.sh
ENTRYPOINT ["/srv/dac/entrypoint.sh"]
CMD ["bash"]
