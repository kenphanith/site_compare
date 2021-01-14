FROM python:3.8-slim

RUN useradd --create-home --shell /bin/bash kenphanith

WORKDIR /home/kenphanith/

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

USER kenphanith

COPY . .

CMD ["bash"]