FROM python:3.9
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD gunicorn --workers=1 --bind 0.0.0.0:5000 app:app







# FROM python:3.9

# WORKDIR /usr/src/app

# COPY ./setup.py ./

# # We copy just the requirements.txt first to leverage Docker cache
# COPY ./requirements.txt ./


# RUN pip install --upgrade pip
# RUN pip install --no-cache-dir -r requirements.txt

# # Let' only copy the required files and folders
# ADD ./config ./config
# ADD ./phishing ./phishing
# COPY ./app.py ./
# ADD ./static ./static
# ADD ./templates ./templates

# EXPOSE 5000

# CMD ["python", "app.py" ]



