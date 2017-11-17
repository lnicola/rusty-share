document.addEventListener("DOMContentLoaded", function () {
    let rows = document.getElementsByTagName("tr");
    if (rows.length > 50) {
        return;
    }
    let playlist = [];
    for (let i = 2; i < rows.length; i++) {
        let anchor = rows[i].children[1].children[0];
        let entry = {
            title: anchor.innerText,
            href: anchor.href
        };
        if (entry.href.endsWith(".mp3") || entry.href.endsWith(".flac")) {
            playlist.push(entry);
        }
    }

    if (playlist.length > 0) {
        playlist.sort(function (a, b) {
            if (a.title < b.title) {
                return -1;
            } else if (a.title > b.title) {
                return 1;
            } else {
                return 0;
            }
        });

        let currentIndex = 0;
        let title = document.createElement("p");
        let titleText = document.createTextNode(playlist[0].title);
        title.appendChild(titleText);
        let audio = new Audio(playlist[0].href);
        audio.controls = true;
        audio.addEventListener("ended", function () {
            if (++currentIndex < playlist.length) {
                this.src = playlist[currentIndex].href;
                titleText.nodeValue = playlist[currentIndex].title;
                audio.play();
            }
        });
        document.body.appendChild(title);
        document.body.appendChild(audio);
    }
});
