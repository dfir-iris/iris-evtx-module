# IrisEVTXModule

An interface module for Evtx2Splunk and Iris in order to ingest Microsoft EVTX log files. The module is installed on IRIS by default.
In case you needed a procedure to install it by yourself, you can follow the one below.

## How to install

### Install evtx2splunk

- Fetch the remote repository AND checkout the branch called `release_irisevtxmodule`
```
$ git clone https://github.com/whikernel/evtx2splunk
$ cd evtx2splunk
$ git checkout release_irisevtxmodule
```

- Install its requirements and the package itself in your IRIS Python environment 
```
$ source /somewhere/iris_venv/bin/activate
(iris_venv) $ pip install .
```

- Copy the `evtxdump_binaries` in your IRIS instance
```
(iris_venv) $ cp -R ./evtxdump_binaries /better/path/accessible/from/iris/instance/ 
```

- Modify the file `evtxdump_binaries/event_bind.json` accordingly to point to the binaries (prefer absolute path)

### Then install IrisEVTXModule package : iris_evtx

- Fetch the remote repository
```
$ git clone https://github.com/Iris-Tim/IrisEVTXModule
```

- Install iris_evtx module in your IRIS Python environment
```
$ source /somewhere/iris_venv/bin/activate
(iris_venv) $ cd IrisEVTXModule
(iris_venv) $ pip install .
```

## How to import in IRIS instance

- Log-in to your IRIS web instance
- Go to "Manage" -> "Advanced" -> "Modules" configuration page
- Add Module
- In the module name text field, set `iris_evtx`
- If the import was successful, a new line should appear showing a new module named "Evtx2Splunk"

## How to configure the module in IRIS instance

- On the Modules page, click on Evtx2Splunk, and configure at least all the necessary fields

## How to use the Evtx2Splunk module

- (Temporary) Restart Iris instance in order to update the available pipelines
- Go to Manage Case
- Create or update a case
- Pick EVTX files, or archive containing EVTX files
- Set Splunk index and optionnaly a hostname
- Import


## License

The contents of this repository is available under [LGPL3 license](LICENSE.txt).


