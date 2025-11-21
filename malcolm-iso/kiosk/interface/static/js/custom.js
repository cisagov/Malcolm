// Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

function start_all() {
    var xhttp = new XMLHttpRequest();
    loadingBar('on');
    xhttp.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            loadingBar('off');
            modal(this.responseText);
        }
    };
    xhttp.open("POST", "/script_call/start --quiet", true);
    xhttp.send();
}


function stop_all() {
    var xhttp = new XMLHttpRequest();
    loadingBar('on');
    xhttp.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            loadingBar('off');
            modal(this.responseText);
        }
    };
    xhttp.open("POST", "/script_call/stop", true);
    xhttp.send();

}

function sensor_status() {
    var xhttp = new XMLHttpRequest();
    loadingBar('on');
    xhttp.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            loadingBar('off');
            modal(this.responseText);
        }
    };
    xhttp.open("POST", "/script_call/status", true);
    xhttp.send();
}

function clean_sensor() {
    if (confirm('This will irreversibly remove captured data. Are you sure?')) {
        var xhttp = new XMLHttpRequest();
        loadingBar('on');
        xhttp.onreadystatechange = function () {
            if (this.readyState === 4 && this.status === 200) {
                loadingBar('off');
                modal(this.responseText);
            }
        };
        xhttp.open("POST", "/script_call/wipe", true);
        xhttp.send();
    }
}

String.prototype.unquoted = function (){return this.replace (/(^")|("$)/g, '')}

function modal(responseText) {

    var modal = document.getElementById('myModal');
    var text = document.getElementById('response_text');
    var closeBtn = document.getElementById("close");

    modal.style.display = "block";

    // try to parse JSON
    let content;
    try {
        const data = JSON.parse(responseText);

        if (data.success) {
            content = data.output;
        } else {
            content =
                `Command: ${data.cmd.join(" ")}\n` +
                `Return code: ${data.returncode}\n` +
                `Out:\n${data.out}\n` +
                `Err:\n${data.err}`;
        }
    } catch (e) {
        // fallback if response isn't JSON
        content = responseText;
    }

    // set content with preserved whitespace and line breaks
    text.textContent = content; // textContent + CSS white-space: pre handles everything

    closeBtn.onclick = function () {
        modal.style.display = "none";
    };

    window.onclick = function (event) {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    };
}

function loadingBar(status) {
    var loading = document.getElementById('myLoading');
    if (status === 'on') {
        loading.style.display = "block";
    } else {
        loading.style.display = "none";
    }
}
