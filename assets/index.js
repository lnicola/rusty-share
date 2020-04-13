https://github.com/github/fetch/issues/89#issuecomment-256610849
function futch(url, opts = {}, onProgress) {
    return new Promise((res, rej) => {
        var xhr = new XMLHttpRequest();
        xhr.open(opts.method || 'get', url);
        for (var k in opts.headers || {})
            xhr.setRequestHeader(k, opts.headers[k]);
        xhr.onload = e => res(e.target.responseText);
        xhr.onerror = rej;
        if (xhr.upload && onProgress)
            xhr.upload.onprogress = onProgress;
        xhr.send(opts.body);
    });
}

document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById('file');
    const btn = document.getElementById("upload");

    function upload(files) {
        for (const file of files) {
            console.log(file);
            const div = document.createElement("div");
            div.appendChild(document.createTextNode(file.name));
            const progress = document.createElement("progress");
            progress.max = file.size;
            div.appendChild(progress);
            document.body.appendChild(div);

            futch(file.name, {
                method: 'put',
                body: file,
            }, e => progress.value = e.loaded).catch(
                error => console.error(error)
            );
        }
    }

    btn.addEventListener("click", () => upload(input.files));
})
