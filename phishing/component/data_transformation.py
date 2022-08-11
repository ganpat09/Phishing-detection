from cgi import test
from sklearn import preprocessing
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as imbpipeline
from phishing.exception import PhishingException
from phishing.logger import logging
from phishing.entity.config_entity import DataTransformationConfig 
from phishing.entity.artifact_entity import DataIngestionArtifact,\
DataValidationArtifact,DataTransformationArtifact
import sys,os
import numpy as np
from sklearn.base import BaseEstimator,TransformerMixin
from sklearn.preprocessing import PowerTransformer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
import pandas as pd
from phishing.constant import *
from phishing.util.util import read_yaml_file,save_object,save_numpy_array_data,load_data

from sklearn.feature_selection import f_regression, mutual_info_regression


#   qty_dot_url : int
#   qty_hyphen_url : int
#   qty_underline_url : int
#   qty_slash_url : int
#   qty_questionmark_url : int
#   qty_equal_url : int
#   qty_at_url : int
#   qty_and_url : int
#   qty_exclamation_url : int
#   qty_space_url : int
#   qty_tilde_url : int
#   qty_comma_url : int
#   qty_plus_url : int
#   qty_asterisk_url : int
#   qty_hashtag_url : int
#   qty_dollar_url : int
#   qty_percent_url : int
#   qty_tld_url : int
#   length_url : int
#   qty_dot_domain : int
#   qty_hyphen_domain : int
#   qty_underline_domain : int
#   qty_slash_domain : int
#   qty_questionmark_domain : int
#   qty_equal_domain : int
#   qty_at_domain : int
#   qty_and_domain : int
#   qty_exclamation_domain : int
#   qty_space_domain : int
#   qty_tilde_domain : int
#   qty_comma_domain : int
#   qty_plus_domain : int
#   qty_asterisk_domain : int
#   qty_hashtag_domain : int
#   qty_dollar_domain : int
#   qty_percent_domain : int
#   qty_vowels_domain : int
#   domain_length : int
#   domain_in_ip : int
#   server_client_domain : int
#   qty_dot_directory : int
#   qty_hyphen_directory : int
#   qty_underline_directory : int
#   qty_slash_directory : int
#   qty_questionmark_directory : int
#   qty_equal_directory : int
#   qty_at_directory : int
#   qty_and_directory : int
#   qty_exclamation_directory : int
#   qty_space_directory : int
#   qty_tilde_directory : int
#   qty_comma_directory : int
#   qty_plus_directory : int
#   qty_asterisk_directory : int
#   qty_hashtag_directory : int
#   qty_dollar_directory : int
#   qty_percent_directory : int
#   directory_length : int
#   qty_dot_file : int
#   qty_hyphen_file : int
#   qty_underline_file : int
#   qty_slash_file : int
#   qty_questionmark_file : int
#   qty_equal_file : int
#   qty_at_file : int
#   qty_and_file : int
#   qty_exclamation_file : int
#   qty_space_file : int
#   qty_tilde_file : int
#   qty_comma_file : int
#   qty_plus_file : int
#   qty_asterisk_file : int
#   qty_hashtag_file : int
#   qty_dollar_file : int
#   qty_percent_file : int
#   file_length : int
#   qty_dot_params : int
#   qty_hyphen_params : int
#   qty_underline_params : int
#   qty_slash_params : int
#   qty_questionmark_params : int
#   qty_equal_params : int
#   qty_at_params : int
#   qty_and_params : int
#   qty_exclamation_params : int
#   qty_space_params : int
#   qty_tilde_params : int
#   qty_comma_params : int
#   qty_plus_params : int
#   qty_asterisk_params : int
#   qty_hashtag_params : int
#   qty_dollar_params : int
#   qty_percent_params : int
#   params_length : int
#   tld_present_params : int
#   qty_params : int
#   email_in_url : int
#   time_response : float
#   domain_spf : int
#   asn_ip : int
#   time_domain_activation : int
#   time_domain_expiration : int
#   qty_ip_resolved : int
#   qty_nameservers : int
#   qty_mx_servers : int
#   ttl_hostname : int
#   tls_ssl_certificate : int
#   qty_redirects : int
#   url_google_index : int
#   domain_google_index : int
#   url_shortened : int
#   phishing : int


class MyDecorrelator(BaseEstimator, TransformerMixin):
    
    def __init__(self, threshold):
        self.threshold = threshold
        self.correlated_columns = None

    def fit(self, X, y=None):
        correlated_features = set()  
        X = pd.DataFrame(X)
        corr_matrix = X.corr()
        for i in range(len(corr_matrix.columns)):
            for j in range(i):
                if abs(corr_matrix.iloc[i, j]) > self.threshold: # we are interested in absolute coeff value
                    colname = corr_matrix.columns[i]  # getting the name of column
                    correlated_features.add(colname)
        self.correlated_features = correlated_features
        return self

    def transform(self, X, y=None, **kwargs):
        return (pd.DataFrame(X)).drop(labels=self.correlated_features, axis=1)


class FeatureGenerator(BaseEstimator, TransformerMixin):

    def __init__(self, columns=None):
        """
        FeatureGenerator Initialization
       
        """
        try:
            self.columns = columns
            
        except Exception as e:
            raise PhishingException(e, sys) from e

    def fit(self, X, y=None):
        return self

    def transform(self, X, y=None):
        try:

            X_df = pd.DataFrame(X,columns=self.columns)
            y_df = pd.DataFrame(y,columns=['phishing'])
            generated_feature = X_df.copy()
          
            zero_std_colunm = generated_feature.std()[generated_feature.std()==0]
           # generated_feature = generated_feature.drop(labels=zero_std_colunm.index,axis=1,errors="ignore")
            
           
            # generated_feature = self.f_test_and_mutual_information(X,y,generated_feature)



            return generated_feature
        except Exception as e:
            raise PhishingException(e, sys) from e

    def f_test_and_mutual_information(self,X,y,filtered_df):
        try:
            filtered_data_copy = filtered_df.copy()
            f_test, _ = f_regression(X, y)
            f_test /= np.max(f_test)

            mi = mutual_info_regression(X, y)
            mi /= np.max(mi)
            print("filtered_data", filtered_data_copy.shape)

            for i in range(len(X.columns)):
                if mi[i] == 0:
                        print(X.columns[i])
                        filtered_data_copy.drop(labels=X.columns[i],axis=1,inplace=True,errors='ignore')

            return filtered_data_copy
        except Exception as e:
            raise PhishingException(e, sys) from e 


    def remove_most_corelated_features(self,X)->pd.DataFrame:
        try:
            corr_data = X.corr()

            l = []


            for k1 in corr_data:
                
                for k2 in corr_data:
                    value = corr_data[k1][k2]
                    if k1 != k2:
                        if value > 0.97:
                            for i in l:
                                if k1 == i[1] and k2 == i[0]:
                                    
                                    break
                            else:
                            
                                l.append((k1,k2,value))


            filtered_data = X.copy()

            for i in l:
                filtered_data.drop(labels=i[0],axis=1,inplace=True,errors='ignore')  

            return filtered_data                        
        except Exception as e:
            raise PhishingException(e,sys)



class DataTransformation:

    def __init__(self, data_transformation_config: DataTransformationConfig,
                 data_ingestion_artifact: DataIngestionArtifact,
                 data_validation_artifact: DataValidationArtifact
                 ):
        try:
            logging.info(f"{'>>' * 30}Data Transformation log started.{'<<' * 30} ")
            self.data_transformation_config= data_transformation_config
            self.data_ingestion_artifact = data_ingestion_artifact
            self.data_validation_artifact = data_validation_artifact

        except Exception as e:
            raise PhishingException(e,sys) from e

    

    def get_data_transformer_object(self)->ColumnTransformer:
        try:
            schema_file_path = self.data_validation_artifact.schema_file_path

            dataset_schema = read_yaml_file(file_path=schema_file_path)

            numerical_columns = dataset_schema[NUMERICAL_COLUMN_KEY]
            #categorical_columns = dataset_schema[CATEGORICAL_COLUMN_KEY]


            num_pipeline = Pipeline(steps=[
                 
               
                
                
               #('imputer', SimpleImputer(strategy="median",missing_values=-1)),
                ('scaler', PowerTransformer()),
                
                ('remove_high_correlated_feature', MyDecorrelator(
                    threshold = 0.96
                )),
            ]
            )

            # cat_pipeline = Pipeline(steps=[
            #      ('impute', SimpleImputer(strategy="most_frequent")),
            #      ('one_hot_encoder', OneHotEncoder()),
            #      ('scaler', StandardScaler(with_mean=False))
            # ]
            # )

            # logging.info(f"Categorical columns: {categorical_columns}")
            logging.info(f"Numerical columns: {numerical_columns}")


            preprocessing = ColumnTransformer([
                ('num_pipeline', num_pipeline, numerical_columns),
                # ('cat_pipeline', cat_pipeline, categorical_columns),
            ])

            return preprocessing

        except Exception as e:
            raise PhishingException(e,sys) from e   


    def initiate_data_transformation(self)->DataTransformationArtifact:
        try:
            logging.info(f"Obtaining preprocessing object.")
            preprocessing_obj = self.get_data_transformer_object()


            logging.info(f"Obtaining training and test file path.")
            train_file_path = self.data_ingestion_artifact.train_file_path
            test_file_path = self.data_ingestion_artifact.test_file_path
            

            schema_file_path = self.data_validation_artifact.schema_file_path
            
            logging.info(f"Loading training and test data as pandas dataframe.")
            train_df = load_data(file_path=train_file_path, schema_file_path=schema_file_path)

            train_df = train_df.drop_duplicates(keep="first")
            
            test_df = load_data(file_path=test_file_path, schema_file_path=schema_file_path)

            test_df = test_df.drop_duplicates(keep="first")


            schema = read_yaml_file(file_path=schema_file_path)

            target_column_name = schema[TARGET_COLUMN_KEY]


            logging.info(f"Splitting input and target feature from training and testing dataframe.")
            input_feature_train_df = train_df.drop(columns=[target_column_name],axis=1)
            target_feature_train_df = train_df[target_column_name]

            input_feature_train_df, target_feature_train_df = SMOTE().fit_resample(input_feature_train_df, target_feature_train_df)

            input_feature_test_df = test_df.drop(columns=[target_column_name],axis=1)
            target_feature_test_df = test_df[target_column_name]

           # input_feature_test_df, target_feature_test_df = SMOTE().fit_resample(input_feature_test_df, target_feature_test_df)
            

            logging.info(f"Applying preprocessing object on training dataframe and testing dataframe")

        
            
            input_feature_train_arr=preprocessing_obj.fit_transform(input_feature_train_df,target_feature_train_df)
            print("input_feature_train_arr #################################",input_feature_train_arr.shape,input_feature_train_df.shape)

            input_feature_test_arr = preprocessing_obj.transform(input_feature_test_df)
            print("input_feature_test_arr #################################",len(input_feature_test_arr.shape))


            train_arr = np.c_[ input_feature_train_arr, np.array(target_feature_train_df)]

            test_arr = np.c_[input_feature_test_arr, np.array(target_feature_test_df)]

            
            transformed_train_dir = self.data_transformation_config.transformed_train_dir
            transformed_test_dir = self.data_transformation_config.transformed_test_dir

            train_file_name = os.path.basename(train_file_path).replace(".csv",".npz")
            test_file_name = os.path.basename(test_file_path).replace(".csv",".npz")

            transformed_train_file_path = os.path.join(transformed_train_dir, train_file_name)
            transformed_test_file_path = os.path.join(transformed_test_dir, test_file_name)

            logging.info(f"Saving transformed training and testing array.")
            
            save_numpy_array_data(file_path=transformed_train_file_path,array=train_arr)
            save_numpy_array_data(file_path=transformed_test_file_path,array=test_arr)

            preprocessing_obj_file_path = self.data_transformation_config.preprocessed_object_file_path

            logging.info(f"Saving preprocessing object.")
            save_object(file_path=preprocessing_obj_file_path,obj=preprocessing_obj)

            data_transformation_artifact = DataTransformationArtifact(is_transformed=True,
            message="Data transformation successfull.",
            transformed_train_file_path=transformed_train_file_path,
            transformed_test_file_path=transformed_test_file_path,
            preprocessed_object_file_path=preprocessing_obj_file_path


            )
            logging.info(f"Data transformationa artifact: {data_transformation_artifact}")
            return data_transformation_artifact
        except Exception as e:
            raise PhishingException(e,sys) from e

    def __del__(self):
        logging.info(f"{'>>'*30}Data Transformation log completed.{'<<'*30} \n\n")