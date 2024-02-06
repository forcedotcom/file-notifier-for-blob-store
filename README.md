
### For Azure, Create new zip file to build
```
zip -r build/function_app.zip function_app.py host.json requirements.txt -x '*__pycache__*'
```

### For GCP, create new zip file
```
zip -r source_code.zip main.py requirements.txt -x '*__pycache__*'
```

### For AWS, create new zip file
```
pyenv virtualenv 3.11.4 aws
pyenv activate aws
pip3 install --platform manylinux2014_x86_64 --target=package --implementation cp \
--python-version 3.11.4 \
--only-binary=:all: --upgrade -r requirements.txt 

cd package
zip -r ../unstructured_package.zip .
cd ..
zip ./unstructured_package.zip unstructured_data.py
```
