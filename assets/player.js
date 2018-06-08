Array.prototype.shuffle = function () {
    var i = this.length, j, temp;
    if (i === 0) {
        return this;
    }
    while (--i) {
        j = Math.floor(Math.random() * (i + 1));
        temp = this[i];
        this[i] = this[j];
        this[j] = temp;
    }
    return this;
}

document.addEventListener("DOMContentLoaded", function () {
    let rows = document.getElementsByTagName("tr");
    if (rows.length > 5000) {
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

    if (playlist.length === 0) {
        return;
    }

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
    let title = document.getElementById("song-title");
    let audio = document.getElementById("player");

    function change() {
        audio.src = playlist[currentIndex].href;
        title.textContent = playlist[currentIndex].title;
    }
    change();

    function next() {
        if (currentIndex < playlist.length - 1) {
            currentIndex++;
            let wasPlaying = !audio.paused;
            change();
            if (wasPlaying) {
                audio.play();
            }
        }
    }
    function prev() {
        if (currentIndex > 0) {
            currentIndex--;
            let wasPlaying = !audio.paused;
            change();
            if (wasPlaying) {
                audio.play();
            }
        }
    }
    audio.addEventListener("ended", next);

    document.getElementById("shuffle").addEventListener("click", function () {
        playlist.shuffle();
        currentIndex = -1;
    });
    document.getElementById("prev").addEventListener("click", prev);
    document.getElementById("next").addEventListener("click", next);
    document.getElementById("player-section").classList.remove("hidden");
});
