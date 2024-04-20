from flask import Flask, request, jsonify
from flask_cors import CORS
from google.cloud import storage
from flask_bcrypt import generate_password_hash, Bcrypt
import pymongo
from pymongo import MongoClient
import bcrypt
import jwt
from datetime import datetime
from bson.regex import Regex
from bson import ObjectId 
import uuid
import spacy
from spacy.lang.ru import Russian
import nltk
from nltk.stem import SnowballStemmer

#from nltk.corpus import stopwords
#from spacy.lang.ru import STOP_WORDS
import pymorphy2
#from Levenshtein import distance
#from gensim.models import FastText
#from nltk.tokenize import word_tokenize
#from scipy.spatial.distance import cosine
#import numpy as np
#from gensim.models import KeyedVectors

app = Flask(__name__)
CORS(app)
storage_client = storage.Client.from_service_account_json("C:/Users/seker/Downloads/inbound-guru-410319-36a73cb47314.json")  
bucket_name = 'docs_ss'  
client = MongoClient('mongodb://localhost:27017/')  
db = client['project2']  
collection = db['ss_works']
users_collection = db['users']
admins_collection = db['admins']
favorite_collection = db['favoriteWork']
vectors_collection = db['vectors_collection']
bcrypt = Bcrypt()
#stop_words = spacy.lang.ru.stop_words
#nlp0 = spacy.load('ru_core_news_md')
nlp = spacy.load("ru_core_news_sm")
stemmer = SnowballStemmer("russian")




@app.route('/upload', methods=['POST'])
def upload_file():
    work_name = request.form.get('workName')
    work_topic = request.form.get('workTopic')
    keywords = request.form.get('keywords')
    co_authors = request.form.get('coAuthors')

    keywords_array = [keyword.strip() for keyword in keywords.split(',') if keyword.strip()]
    co_authors_array = [co_author.strip() for co_author in co_authors.split(',') if co_author.strip()]

    authorization_header = request.headers.get('Authorization')

   

    if not authorization_header:
        return 'Authorization header not provided', 401

    token = authorization_header.split(' ')[1]
    print(f'Token: {token}')

    try:
        decoded_token = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        email = decoded_token.get('email')
    except jwt.ExpiredSignatureError:
        return 'Expired token', 401
    except jwt.InvalidTokenError:
        return 'Invalid token', 401

    file = request.files['file']

    if file.filename == '':
        return 'Файл не выбран', 400

    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(f'works/{file.filename}')
        blob.upload_from_file(file)
        blob.make_public()
        public_url = f'{blob.public_url}?random={uuid.uuid4()}'
        print(public_url)
        document = {
            'workName': work_name,
            'workTopic': work_topic,
            'keywords': keywords_array,
            'author': email,
            'coAuthors': co_authors_array,
            'publicationDate': datetime.utcnow(),
            'fileLink': public_url,
        }
        result = collection.insert_one(document)
       

        return 'Файл успешно загружен в Google Cloud Storage в папку "works"'
    except Exception as e:
        return f'Ошибка при загрузке файла: {e}', 500
    



@app.route('/search', methods=['POST'])
def search_by_work_name():
    data = request.get_json()
    transcript = data.get('transcript')
    print(transcript)
    doc = nlp(transcript)
    
    lemmatized_stemmed_text = [stemmer.stem(token.lemma_.lower()) for token in doc if token.is_alpha and not token.is_stop]
    print(lemmatized_stemmed_text)
    
    search_results = collection.find(
    {
        '$text': {'$search': ' '.join(lemmatized_stemmed_text)}
    },
    {'score': {'$meta': 'textScore'}, 'workTopic': 1,"workName":1,})
    print(search_results)
    search_results_list = list(search_results.sort([('score', pymongo.DESCENDING)]))

    filtered_results = []
    for result in search_results_list:
        work_topic = result.get('workTopic', '')  
        work_name = result.get('workName', '')  
        lemmatized_stemmed_topic = [stemmer.stem(token.lemma_.lower()) for token in nlp(work_topic) if token.is_alpha and not token.is_stop]
        lemmatized_stemmed_name = [stemmer.stem(token.lemma_.lower()) for token in nlp(work_name) if token.is_alpha and not token.is_stop]
        print("topic",lemmatized_stemmed_topic)
        print("name",lemmatized_stemmed_name)
        

        if all(word in lemmatized_stemmed_name for word in lemmatized_stemmed_text):
            filtered_results.append(result)
            print("result", result)
        else:
            missing_words = [word for word in lemmatized_stemmed_text if word not in lemmatized_stemmed_name]
            print("missing words",missing_words)
            if all(word in lemmatized_stemmed_topic for word in missing_words):
                filtered_results.append(result)
                print("result", result)



    filtered_results.sort(key=lambda x: x.get('score', 0), reverse=True)

    result_ids = [str(result['_id']) for result in filtered_results]
    print(result_ids)
    for result in filtered_results:
        work_name = result.get('workName', 'Unknown Work')
        print(f"Work ID: {result['_id']}, Work Name: {work_name}, Score: {result.get('score', 0)}")

    return jsonify({'result': result_ids})





@app.route('/admin/get_admin', methods=['GET'])
def get_admin():
    try:
        email = request.args.get('email', '')
        
        admin_data = admins_collection.find_one({'email': email}, {'_id': 0, 'passwordHash': 0})

        if admin_data:
            return jsonify({'success': True, 'admin': admin_data}), 200
        else:
            return jsonify({'success': False, 'message': 'Админ не найден'}), 404

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/admin/create_admin', methods=['POST'])
def create_admin():
    try:
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirmPassword', '')
        username = request.form.get('username', '')
        photo = request.files.get('photo')

        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Пароль и подтверждение пароля не совпадают'}), 400

        existing_admin = admins_collection.find_one({'email': email})
        if existing_admin:
            return jsonify({'success': False, 'message': 'Админ с такой почтой уже существует'}), 400

        hashed_password = generate_password_hash(password, rounds=12).decode('utf-8')

        try:
            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(f'admins/pfps/{username}.jpg')  
            blob.upload_from_file(photo)
            photo_url = blob.public_url 
        except Exception as e:
            return jsonify({'success': False, 'message': f'Ошибка при загрузке фотографии: {e}'}), 500

        admin_data = {
            'email': email,
            'passwordHash': hashed_password,
            'username': username,
            'photo_url': photo_url,
        }

        admins_collection.insert_one(admin_data)

        return jsonify({'success': True, 'message': 'Админ успешно создан'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500



@app.route('/register', methods=['POST'])
def register():
    print(request.form)
    print(request.files)
    email = request.form['email']
    phone = request.form['phone']
    first_name = request.form['firstName']
    last_name = request.form['lastName']
    patronymic = request.form.get('patronymic', '')  
    password = request.form['password']
    photo = request.files['photo'] 
    gender = request.form['gender']
    hashed_password = generate_password_hash(password, rounds=12).decode('utf-8')
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(f'pfps/{first_name}.jpg')  
        blob.upload_from_file(photo)
        photo_url = blob.public_url 
    except Exception as e:
        return f'Ошибка при загрузке фотографии: {e}', 500
    
    user_data = {
        'email': email,
        'phone': phone,
        'first_name': first_name,
        'last_name': last_name,
        'patronymic': patronymic,
        'password': hashed_password,
        'gender': gender,
        'photo_url': photo_url
    }

    existing_email = users_collection.find_one({'email': email})
    existing_phone = users_collection.find_one({'phone': phone})
    if existing_email or existing_phone:
        return jsonify({'error': 'Такой пользователь уже зарегестрирован'}), 409
        blob.delete()
    else:
        users_collection.insert_one(user_data)
        return f'Регистрация прошла успешно'

@app.route('/works', methods=['GET'])
def get_all_works():
    all_works = list(collection.find())
    works_data = []
    for work in all_works:
        author_email = work.get('author', '')
        author = users_collection.find_one({'email': author_email})

        work_data = {
            'id': str(work.get('_id', '')),  
            'workName': work.get('workName', ''),
            'workTopic': work.get('workTopic', ''),
            'keywords': work.get('keywords', []),
            'author': work.get('author', ''),
            'author': {
                'email': author_email,
                'first_name': author.get('first_name', ''),
                'last_name': author.get('last_name', ''),
                'photo_url': author.get('photo_url', ''),
                'phone': author.get('phone', '')

            },
            'fileLink': work.get('fileLink', ''),
            'coAuthors':work.get('coAuthors',[]),
            'publicationDate':work.get('publicationDate',''),
        }
        works_data.append(work_data)

    return jsonify(works_data)


@app.route("/works/<string:work_id>", methods=['GET'])
def get_work_by_id(work_id):
    try:
        id = ObjectId(work_id)
        print(id)
        work_object = collection.find_one({'_id': id})
        author_email = work_object['author']
        author = users_collection.find_one({'email': author_email})
        result = {
            'id': work_id,
            'workName': work_object['workName'],
            'workTopic': work_object['workTopic'],
            'keywords': work_object['keywords'],
            'author': work_object['author'],
            'fileLink': work_object['fileLink'],
            'coAuthors': work_object['coAuthors'],
            'publicationDate': work_object['publicationDate'],
            'authorInfo': {
                'email': author_email,
                'first_name': author.get('first_name', ''),
                'last_name': author.get('last_name', ''),
                'photo_url': author.get('photo_url', ''),
                'phone': author.get('phone', ''),
                '_id': str(author.get('_id', ''))  
            }
        }
        return jsonify({"result" : result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.form['email']
        password = request.form['password']
        print(request.form)
        user = users_collection.find_one({'email': email})
        if user and bcrypt.check_password_hash(user['password'], password):
            token = jwt.encode({'email': email}, 'secret_key', algorithm='HS256')
            print(token)
            return jsonify({'message': 'Авторизация успешна', 'access_token': token}), 200

        return jsonify({'message': 'Неверные учетные данные'}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401


@app.route('/admin_login', methods=['POST'])
def admin_login():
    try:
        email = request.form['email']
        password = request.form['password']
        print(request.form)
        admin = admins_collection.find_one({'email': email})
        if admin and bcrypt.check_password_hash(admin['passwordHash'], password):
            token = jwt.encode({'email': email}, 'secret_key', algorithm='HS256')
            print(token)
            return jsonify({'message': 'Авторизация админа успешна', 'admin_token': token}), 200

        return jsonify({'message': 'Неверные учетные данные'}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401


@app.route('/admin/work/<string:work_id>', methods=['GET'])
def get_work(work_id):
    print(work_id)
    work = collection.find_one({'_id': ObjectId(work_id)})
    if work:
        work['_id'] = str(work['_id'])
        return jsonify({'work': work})
    else:
        return jsonify({'message': 'Work not found'}), 404


@app.route('/admin/work/<string:work_id>', methods=['PUT'])
def update_work(work_id):
    data = request.json
    print(work_id)
    print(data)
    data.pop('_id', None)

    result = collection.update_one({'_id': ObjectId(work_id)}, {'$set': data})
    
    if result.modified_count > 0:
        return jsonify({'message': 'Work updated successfully'})
    else:
        return jsonify({'message': 'Work not found or no changes made'}), 404


@app.route('/admin/work/<string:work_id>', methods=['DELETE'])
def delete_work(work_id):
    result = collection.delete_one({'_id': ObjectId(work_id)})

    if result.deleted_count > 0:
        db['vectors_collection'].delete_one({'work_id': ObjectId(work_id)})

        return jsonify({'message': 'Work deleted successfully'})
    else:
        return jsonify({'message': 'Work not found'}), 404


@app.route('/admin/users', methods=['GET'])
def get_all_users():
    users = users_collection.find({}, {'password': 0})  
    user_list = list(users)  

    user_list_serialized = []
    for user in user_list:
        user['_id'] = str(user['_id'])
        if 'works' in user:
            user['works'] = [str(work_id) for work_id in user['works']]
        user_list_serialized.append(user)

    return jsonify({'users': user_list_serialized})


@app.route('/admin/user/<string:user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if user:
            user_email = user['email']
            
            collection.delete_many({'author': user_email})

            result = users_collection.delete_one({'_id': ObjectId(user_id)})
            
            if result.deleted_count > 0:
                return jsonify({'message': 'User and associated works deleted successfully'})
            else:
                return jsonify({'message': 'User not found'}), 404
        else:
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'message': f'Error deleting user: {str(e)}'}), 500




def upload_file_to_storage(file, file_name):
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(file_name)
    blob.upload_from_file(file)
    return blob.public_url

@app.route('/admin/user/<user_id>', methods=['GET', 'PUT'])
def user_profile(user_id):
    if request.method == 'GET':
        try:
            user = users_collection.aggregate([
                {
                    '$match': {'_id': ObjectId(user_id)}
                },
                {
                    '$project': {
                        '_id': 1,
                        'email': 1,
                        'first_name': 1,
                        'gender': 1,
                        'last_name': 1,
                        'patronymic': 1,
                        'phone': 1,
                        'photo_url': 1,
                        'username': 1,
                        'password':1,
                    }
                }
            ])

            user = list(user)
            if user:
                user[0]['_id'] = str(user[0]['_id'])
                return jsonify({'user': user[0]})
            else:
                return jsonify({'error': 'User not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    elif request.method == 'PUT':
        try:
            data = request.form.to_dict(flat=True)  
            photo_file = request.files.get('photo')
            data['gender'] = data['gender']  
            print(data)
            # if 'gender' in data:
            #     data['gender'] = 'male' if data['gender'] == 'Мужской' else 'female'

            if photo_file:
                print(photo_file)
                file_name = f"{ObjectId()}.jpg"
                photo_url = upload_file_to_storage(photo_file, file_name)
                data['photo_url'] = photo_url
            data.pop('_id', None)

            user_id_object = ObjectId(user_id)
            print(data)
            users_collection.update_one({'_id': user_id_object}, {'$set': data})

            return jsonify({'message': 'User profile updated successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500


@app.route('/user_profile_header', methods=['GET'])
def get_user_profile_header():
    try:
        authorization_header = request.headers.get('Authorization')
        if not authorization_header:
            return jsonify({'error': 'Authorization header not provided'}), 401

        token = authorization_header.split(' ')[1]
        print(f'Token: {token}')
        def serialize_document(doc):
            if '_id' in doc:
                doc['_id'] = str(doc['_id'])
            if 'works' in doc:
                doc['works'] = [str(work_id) for work_id in doc['works']]
            if 'userWorks' in doc:
                for work in doc['userWorks']:
                    if '_id' in work:
                        work['_id'] = str(work['_id'])
            return doc
        try:
            decoded_token = jwt.decode(token, 'secret_key', algorithms=['HS256'])
            email = decoded_token.get('email')

            profile_data = users_collection.aggregate([
                {
                    '$match': {'email': email}
                },
                {
                    '$lookup': {
                        'from': 'ss_works',
                        'localField': 'email',
                        'foreignField': 'author',
                        'as': 'userWorks'
                    }
                }
            ])

            profile_data = list(profile_data)
            if profile_data:
                profile_data[0] = serialize_document(profile_data[0])
                
                return jsonify({'profile': profile_data[0]})
            else:
                return jsonify({'error': 'User not found'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Expired token'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/user_profile/<user_id>', methods=['GET'])
def get_user_profile(user_id):
    try:

        # Получаем user_id из параметров URL и преобразуем его в ObjectId
        user_id_object = ObjectId(user_id)
        def serialize_document(doc):
            if '_id' in doc:
                doc['_id'] = str(doc['_id'])
            if 'works' in doc:
                doc['works'] = [str(work_id) for work_id in doc['works']]
            if 'userWorks' in doc:
                for work in doc['userWorks']:
                    if '_id' in work:
                        work['_id'] = str(work['_id'])
            return doc
        profile_data = users_collection.aggregate([
            {
                '$match': {'_id': user_id_object}
            },
            {
                '$lookup': {
                    'from': 'ss_works',
                    'localField': 'email',
                    'foreignField': 'author',
                    'as': 'userWorks'
                }
            }
        ])

        profile_data = list(profile_data)
        if profile_data:
            # Сериализуем данные профиля пользователя
            profile_data[0] = serialize_document(profile_data[0])
            return jsonify({'profile': profile_data[0]})
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/work/<string:work_id>', methods=['PUT'])
def update_work_user(work_id):
    try:
        data = request.form.to_dict()
        print(data)

        if 'file' in request.files:
            file = request.files['file']
            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(f'works/{file.filename}')
            blob.upload_from_file(file)
            blob.make_public()
            public_url = f'{blob.public_url}?random={uuid.uuid4()}'
            print(public_url)
            data['fileLink'] = public_url

        if 'keywords' in data and not isinstance(data['keywords'], list):
            data['keywords'] = [data['keywords']]
        
        if 'coAuthors' in data and not isinstance(data['coAuthors'], list):
            data['coAuthors'] = [data['coAuthors']]

        result = collection.update_one({'_id': ObjectId(work_id)}, {'$set': data})
        if result.modified_count > 0:
            return 'Данные работы обновлены успешно'
        else:
            return 'Работа не найдена или изменений не было', 404

    except Exception as e:
        return f'Ошибка при обновлении данных работы: {e}', 500


@app.route('/get_favorites', methods=['GET'])
def get_favorites():
    try:
        token = request.headers.get('Authorization')  
        decoded_token = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        email = decoded_token.get('email')
        
        user_favorite = favorite_collection.find_one({'userEmail': email})
        if not user_favorite:
            user_favorite = {'userEmail': email, 'workIds': []}
        
        return jsonify({'success': True, 'favorites': user_favorite['workIds']})
    except jwt.ExpiredSignatureError:
        return 'Expired token', 401
    except jwt.InvalidTokenError:
        return 'Invalid token', 401


@app.route('/add_to_favorites', methods=['POST'])
def add_to_favorites():
    data = request.get_json()
    token = data.get('token')
    work_id = data.get('workId')
    try:
        decoded_token = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        email = decoded_token.get('email')
        user_favorite = favorite_collection.find_one({'userEmail': email})

        if not user_favorite:
            user_favorite = {'userEmail': email, 'workIds': []}

        if work_id not in user_favorite['workIds']:
            user_favorite['workIds'].append(work_id)

            favorite_collection.update_one({'userEmail': email}, {'$set': user_favorite}, upsert=True)

            return jsonify({'success': True})
        else:
            return jsonify({'message': 'Work is already in favorites'})

    except jwt.ExpiredSignatureError:
        return 'Expired token', 401
    except jwt.InvalidTokenError:
        return 'Invalid token', 401


@app.route('/remove_from_favorites', methods=['POST'])
def remove_from_favorites():
    data = request.get_json()
    token = data.get('token')
    work_id = data.get('workId')

    try:
        decoded_token = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        email = decoded_token.get('email')

        user_favorite = favorite_collection.find_one({'userEmail': email})

        if user_favorite:
            if work_id in user_favorite['workIds']:
                user_favorite['workIds'].remove(work_id)

                favorite_collection.update_one({'userEmail': email}, {'$set': user_favorite})
                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'message': 'Work not found in favorites'})
        else:
            return jsonify({'success': False, 'message': 'User not found in favorites'})

    except jwt.ExpiredSignatureError:
        return jsonify({'success': False, 'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'success': False, 'message': 'Invalid token'}), 401

        
@app.route('/get_user_favorites', methods=['GET'])
def get_user_favorites():
    try:
        authorization_header = request.headers.get('Authorization')
        if not authorization_header:
            return jsonify({'error': 'Authorization header not provided'}), 401

        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        email = decoded_token.get('email')

        user_favorite = favorite_collection.find_one({'userEmail': email})
        if not user_favorite:
            user_favorite = {'userEmail': email, 'workIds': []}

        user_favorites_ids = user_favorite['workIds']

        user_favorites_data = []
        for work_id in user_favorites_ids:
            work_object = collection.find_one({'_id': ObjectId(work_id)})

            if work_object:
                author_email = work_object['author']
                author = users_collection.find_one({'email': author_email})
                result = {
                    'id': work_id,
                    'workName': work_object['workName'],
                    'workTopic': work_object['workTopic'],
                    'keywords': work_object['keywords'],
                    'author': work_object['author'],
                    'fileLink': work_object['fileLink'],
                    'coAuthors': work_object['coAuthors'],
                    'publicationDate': work_object['publicationDate'],
                    'authorInfo': {
                        'email': author_email,
                        'first_name': author.get('first_name', ''),
                        'last_name': author.get('last_name', ''),
                        'photo_url': author.get('photo_url', ''),
                        'phone': author.get('phone', ''),
                    }
                }
                user_favorites_data.append(result)

        return jsonify({'user_favorites': user_favorites_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/change_password', methods=['POST'])
def change_password():
    try:
        token = request.json.get('token', '')
        decoded_token = jwt.decode(token, 'secret_key', algorithms=['HS256'])
        email = decoded_token.get('email')
        user = users_collection.find_one({'email': email})

        if not user:
            return jsonify({'success': False, 'message': 'Пользователь не найден'}), 404

        old_password = request.json.get('oldPassword', '')
        new_password = request.json.get('newPassword', '')
        confirm_password = request.json.get('confirmPassword', '')

        if not bcrypt.check_password_hash(user['password'], old_password):
            return jsonify({'success': False, 'message': 'Старый пароль введен неверно'}), 400

        if new_password != confirm_password:
            return jsonify({'success': False, 'message': 'Новый пароль и подтверждение не совпадают'}), 400

        hashed_new_password = generate_password_hash(new_password, rounds=12).decode('utf-8')

        users_collection.update_one({'email': email}, {'$set': {'password': hashed_new_password}})

        return jsonify({'success': True, 'message': 'Пароль успешно изменен'}), 200

    except Exception as e:
        print(f'Error changing password: {e}')
        return jsonify({'success': False, 'message': 'Произошла ошибка при изменении пароля'}), 500




if __name__ == '__main__':
    app.run(debug=True, port=5000)
