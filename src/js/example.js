// @ts-check
const { use } = import.meta;
const { Pipe } = use('streams');
const { encodeString } = use('engine');
const { setInterval, clearInterval } = use('timers');
const console = use('console');

const $s = use('server').createServer({
    port: 8080,
    onRequest(req, res){
        console.log(req.method, req.url, req.httpVersion);
        if(req.url.includes('sse')){
            // example of server-sent events
            // note: upgrade() is used to test, 
            //      in deployment it is recommended to be replaced with res.send()
            res.writeHead(200, {
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache"
            });
            const fd = res.upgrade();
            const pipe = new Pipe();
            pipe.open(fd);
            const iv = setInterval(() => {
                pipe.write(encodeString(`data: ${new Date().toLocaleString()} \n\n`))
                    .catch(err => {
                        console.log(err);
                        clearInterval(iv);
                    });
            }, 1000);
        }else{
            res.send(200, "Hello, world!\n Time:" + new Date().toLocaleString());
        }
    },
    onBody(req, res){
        console.log('Received body:', req.body);
    },
    onError(err, req, res){
        console.log(err);
        console.log('Error:', req, res);
    }
});