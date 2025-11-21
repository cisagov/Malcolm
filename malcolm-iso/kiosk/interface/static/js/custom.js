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
    xhttp.open("POST", "/script_call/start all", true);
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
    xhttp.open("POST", "/script_call/stop all", true);
    xhttp.send();

}

function start_zeek() {
    var xhttp = new XMLHttpRequest();
    loadingBar('on');
    xhttp.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            loadingBar('off');
            modal(this.responseText);
        }
    };
    xhttp.open("POST", "/script_call/start zeek:*", true);
    xhttp.send();
}

function stop_zeek() {
    var xhttp = new XMLHttpRequest();
    loadingBar('on');
    xhttp.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            loadingBar('off');
            modal(this.responseText);
        }
    };
    xhttp.open("POST", "/script_call/stop zeek:*", true);
    xhttp.send();

}

function start_tcp() {
    var xhttp = new XMLHttpRequest();
    loadingBar('on');
    xhttp.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            loadingBar('off');
            modal(this.responseText);
        }
    };
    xhttp.open("POST", "/script_call/start tcpdump:*", true);
    xhttp.send();

}

function stop_tcp() {
    var xhttp = new XMLHttpRequest();
    loadingBar('on');
    xhttp.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            loadingBar('off');
            modal(this.responseText);
        }
    };
    xhttp.open("POST", "/script_call/stop tcpdump:*", true);
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
    xhttp.open("POST", "/script_call/status all", true);
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
        xhttp.open("POST", "/script_call/clean all", true);
        xhttp.send();
    }
}

String.prototype.unquoted = function (){return this.replace (/(^")|("$)/g, '')}

function modal(responseText) {

    var modal = document.getElementById('myModal');
    var text = document.getElementById('response_text');
    var closeBtn = document.getElementById("close");

    modal.style.display = "block";

    text.innerHTML = responseText.split("\\n").join("<br>").unquoted();

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
