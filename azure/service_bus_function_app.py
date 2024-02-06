import azure.functions as func
import logging
import json

app = func.FunctionApp()

@app.function_name(name="ServiceBusQueueTrigger1")
@app.service_bus_queue_trigger(arg_name="msg",
                               queue_name="unstructured-queue",
                               connection="MY_SERVICE_BUS")
def serviceBusFunction(msg: func.ServiceBusMessage):
    event = {'id': msg.message_id}
    logging.info('serviceBusMsg: %s', json.dumps(event))
    bytes_data = msg.get_body()
    my_json = bytes_data.decode('utf8').replace("'", '"')
    data = json.loads(my_json)
    logging.info('json: %s', json.dumps(data, indent=4, sort_keys=True))
