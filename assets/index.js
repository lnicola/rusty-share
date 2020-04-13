document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById('file');
    const btn = document.getElementById("upload");

    const upload = (file) => {
        console.log(file);
        fetch(file.name, {
            method: 'put',
            body: file
        }).catch(
            error => console.error(error)
        );
    };

    btn.addEventListener("click", () => upload(input.files[0]));
})
