const console = import.meta.use('console')
const worker = import.meta.use('worker')

if (worker.isWorker) {
    console.log('worker:', worker.workerData)
    console.log('worker env:', worker)
    worker.pipe.onmessage = (data) => {
        console.log('worker:', data)
        worker.pipe.postMessage('hello world');
    }
} else {
    console.log('main')
    const w = new worker.Worker('worker message');
    w.messagePipe.postMessage('hello world');
    w.messagePipe.onmessage = (data) => {
        console.log('main:', data)
    }
    queueMicrotask(() => {
        console.log(w)  // no exit!
    })
}