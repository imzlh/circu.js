const console = import.meta.use('console');

for (const key of import.meta.module){
    console.log(import.meta.use(key));
}