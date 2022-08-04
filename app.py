from asyncio.log import logger
from flask import Flask, request
import sys

import pip
from phishing.util.util import read_yaml_file, write_yaml_file
from matplotlib.style import context
from phishing.logger import logging
from phishing.exception import PhishingException
import os, sys
import json
from phishing.config.configuration import Configuartion
from phishing.constant import CONFIG_DIR, STATIC_DIR, get_current_time_stamp
from phishing.pipeline.pipeline import Pipeline
from phishing.entity.phishing_predictor import HousingPredictor, PhisingUrlData
from flask import send_file, abort, render_template
from sklearn.metrics import classification_report

import pandas as pd

import validators


ROOT_DIR = os.getcwd()
LOG_FOLDER_NAME = "logs"
PIPELINE_FOLDER_NAME = "phishing"
SAVED_MODELS_DIR_NAME = "saved_models"
MODEL_CONFIG_FILE_PATH = os.path.join(ROOT_DIR, CONFIG_DIR, "model.yaml")
LOG_DIR = os.path.join(ROOT_DIR, LOG_FOLDER_NAME)
PIPELINE_DIR = os.path.join(ROOT_DIR, PIPELINE_FOLDER_NAME)
MODEL_DIR = os.path.join(ROOT_DIR, SAVED_MODELS_DIR_NAME)
STATIC_PATH = os.path.join(ROOT_DIR,STATIC_DIR)

from phishing.logger import get_log_dataframe

PHISHING_DATA_KEY = "phishing_data"
PHISHING_VALUE_KEY = "phishing_value"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = STATIC_PATH


@app.route('/artifact', defaults={'req_path': 'phishing_detection'})
@app.route('/artifact/<path:req_path>')
def render_artifact_dir(req_path):
    os.makedirs("phishing_detection", exist_ok=True)
    # Joining the base and the requested path
    print(f"req_path: {req_path}")
    abs_path = os.path.join(req_path)
    print(abs_path)
    # Return 404 if path doesn't exist
    if not os.path.exists(abs_path):
        return abort(404)

    # Check if path is a file and serve
    if os.path.isfile(abs_path):
        if ".html" in abs_path:
            with open(abs_path, "r", encoding="utf-8") as file:
                content = ''
                for line in file.readlines():
                    content = f"{content}{line}"
                return content
        return send_file(abs_path)

    # Show directory contents
    files = {os.path.join(abs_path, file_name): file_name for file_name in os.listdir(abs_path) if
             "artifact" in os.path.join(abs_path, file_name)}

    result = {
        "files": files,
        "parent_folder": os.path.dirname(abs_path),
        "parent_label": abs_path
    }
    return render_template('files.html', result=result)


@app.route('/', methods=['GET', 'POST'])
def index():
    try:
        demo_img = os.path.join(app.config['UPLOAD_FOLDER'], '88_url.png')
        return render_template('index.html',demo_img = demo_img)
    except Exception as e:
        return str(e)


@app.route('/view_experiment_hist', methods=['GET', 'POST'])
def view_experiment_history():
    experiment_df = Pipeline.get_experiments_status()
    
    context = {
        "experiment": experiment_df.to_html(classes='table table-striped col-12')
    }
    return render_template('experiment_history.html', context=context)


@app.route('/train', methods=['GET', 'POST'])
def train():
    try:
        message = ""
        pipeline = Pipeline(config=Configuartion(current_time_stamp=get_current_time_stamp()))
        pipeline.run()
        if not Pipeline.experiment.running_status:
            message = "Training started."
            pipeline.start()
        else:
            message = "Training is already in progress."
        context = {
            "experiment": pipeline.get_experiments_status().to_html(classes='table table-striped col-12'),
            "message": message
        }
        return render_template('train.html', context=context)
    except Exception as e:
            logging.exception(e)
            context = {
            "experiment": "<div></div>",
            "message": e
        }
            return render_template('train.html', context=context)


@app.route('/predict', methods=['GET', 'POST'])
def predict():
    context = {
        PHISHING_DATA_KEY: None,
        PHISHING_VALUE_KEY: None
    }

    if request.method == 'POST':
        url = request.form['url']
        if not validators.url(url):
            return 
        

        try:
                phising_data = PhisingUrlData(check_url = url)
                phishing_df = phising_data.get_phishing_input_data_frame()
                phishing_predictor = HousingPredictor(model_dir=MODEL_DIR)
                phishing_value = phishing_predictor.predict(X=phishing_df)
                #print(url,"is phissing", median_phishing_value)

                if phishing_value > 0:
                    phishing_value = "This site will Phishing Site "
                else:
                    phishing_value = "This site will Legitimate Site"
                # phising_data.get_url_extract_data_as_dict()
                context = {
                    PHISHING_DATA_KEY: {} ,
                    PHISHING_VALUE_KEY: phishing_value,
                }
                return render_template('predict.html', context=context)

        except Exception as e:
            logging.exception(e)
            
            context = {
            PHISHING_DATA_KEY: {} ,
            PHISHING_VALUE_KEY: e,
            }
            return render_template('predict.html', context=context) 
    return render_template("predict.html", context=context)


@app.route('/saved_models', defaults={'req_path': 'saved_models'})
@app.route('/saved_models/<path:req_path>')
def saved_models_dir(req_path):
    os.makedirs("saved_models", exist_ok=True)
    # Joining the base and the requested path
    print(f"req_path: {req_path}")
    abs_path = os.path.join(req_path)
    print(abs_path)
    # Return 404 if path doesn't exist
    if not os.path.exists(abs_path):
        return abort(404)

    # Check if path is a file and serve
    if os.path.isfile(abs_path):
        return send_file(abs_path)

    # Show directory contents
    files = {os.path.join(abs_path, file): file for file in os.listdir(abs_path)}

    result = {
        "files": files,
        "parent_folder": os.path.dirname(abs_path),
        "parent_label": abs_path
    }
    return render_template('saved_models_files.html', result=result)


@app.route("/update_model_config", methods=['GET', 'POST'])
def update_model_config():
    try:
        if request.method == 'POST':
            model_config = request.form['new_model_config']
            model_config = model_config.replace("'", '"')
            print(model_config)
            model_config = json.loads(model_config)

            write_yaml_file(file_path=MODEL_CONFIG_FILE_PATH, data=model_config)

        model_config = read_yaml_file(file_path=MODEL_CONFIG_FILE_PATH)
        return render_template('update_model.html', result={"model_config": model_config})

    except  Exception as e:
        logging.exception(e)
        return str(e)


@app.route(f'/logs', defaults={'req_path': f'{LOG_FOLDER_NAME}'})
@app.route(f'/{LOG_FOLDER_NAME}/<path:req_path>')
def render_log_dir(req_path):
    os.makedirs(LOG_FOLDER_NAME, exist_ok=True)
    # Joining the base and the requested path
    logging.info(f"req_path: {req_path}")
    abs_path = os.path.join(req_path)
    print(abs_path)
    # Return 404 if path doesn't exist
    if not os.path.exists(abs_path):
        return abort(404)

    # Check if path is a file and serve
    if os.path.isfile(abs_path):
        log_df = get_log_dataframe(abs_path)
        context = {"log": log_df.to_html(classes="table-striped", index=False)}
        return render_template('log.html', context=context)

    # Show directory contents
    files = {os.path.join(abs_path, file): file for file in os.listdir(abs_path)}

    result = {
        "files": files,
        "parent_folder": os.path.dirname(abs_path),
        "parent_label": abs_path
    }
    return render_template('log_files.html', result=result)


@app.route("/upload", methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        print(request.files['file'])
        f = request.files['file']
        data_xls = pd.read_excel(f, engine='openpyxl')[0:101]

        y_true = data_xls['Labels']
        
        phishing_df, y_pred_ix = get_df_extract_urls(data_xls['url'])
        
        phishing_predictor = HousingPredictor(model_dir=MODEL_DIR)
        y_pred = phishing_predictor.predict(X=phishing_df)



        
        print(len(y_pred))
        print(classification_report(y_true.iloc[y_pred_ix], y_pred))

        return classification_report(y_true.iloc[y_pred_ix], y_pred)
    return '''
    <!doctype html>
    <title>Upload an excel file</title>
    <h1>Excel file upload (csv, tsv, csvz, tsvz only)</h1>
    <form action="" method=post enctype=multipart/form-data>
    <p><input type=file name=file><input type=submit value=Upload>
    </form>
    '''


def get_df_extract_urls(urls)->pd.DataFrame:
    li = []
    lix = []
    for id, url in enumerate(urls):
        try:
            phising_data = PhisingUrlData(check_url = url)
            phising_df = phising_data.get_phishing_input_data_frame()
            li.append(phising_df)
            lix.append(id)
            #logger("######################",id)
        except Exception as e:
            #print(e)
            pass
    return pd.concat(li), lix       

if __name__ == "__main__":
    app.run(debug=True)
