const analyzeButton =
    document.getElementById(
        "analyzeButton"
    );


const progressContainer =
    document.getElementById(
        "progressContainer"
    );


const progress =
    document.getElementById(
        "progress"
    );


const progressStage =
    document.getElementById(
        "progressStage"
    );


const progressPercent =
    document.getElementById(
        "progressPercent"
    );

const importButton =
    document.getElementById(
        "importButton"
    );


const evidenceModal =
    document.getElementById(
        "evidenceModal"
    );


const closeModalButton =
    document.getElementById(
        "closeModalButton"
    );


const cancelImportButton =
    document.getElementById(
        "cancelImportButton"
    );


const confirmImportButton =
    document.getElementById(
        "confirmImportButton"
    );


const evidenceList =
    document.getElementById(
        "evidenceList"
    );


let selectedEvidence = null;

let pollingInterval = null;


/* =========================
   Analysis
========================= */


analyzeButton.addEventListener(
    "click",
    startAnalysis
);


async function startAnalysis() {

    analyzeButton.disabled = true;

    progressContainer.style.display =
        "block";


    const response =
        await fetch(
            "/api/analyze",
            {
                method: "POST"
            }
        );


    if (!response.ok) {

        alert(
            "Failed to start analysis."
        );

        analyzeButton.disabled = false;

        return;
    }


    pollingInterval =
        setInterval(
            updateStatus,
            500
        );
}

/* =========================
   Evidence Import
========================= */


importButton.addEventListener(
    "click",
    openEvidenceModal
);


closeModalButton.addEventListener(
    "click",
    closeEvidenceModal
);


cancelImportButton.addEventListener(
    "click",
    closeEvidenceModal
);


async function openEvidenceModal() {

    evidenceModal.classList.add(
        "visible"
    );

    selectedEvidence = null;

    confirmImportButton.disabled = true;

    evidenceList.innerHTML = `
        <div class="subtitle">
            Loading evidence...
        </div>
    `;


    try {

        const response =
            await fetch(
                "/api/evidence"
            );


        if (!response.ok) {
            throw new Error(
                "Failed to load evidence"
            );
        }


        const data =
            await response.json();


        renderEvidenceList(
            data.evidence
        );


    } catch (error) {

        console.error(error);

        evidenceList.innerHTML = `
            <div class="subtitle">
                Failed to load evidence.
            </div>
        `;
    }
}


function closeEvidenceModal() {

    evidenceModal.classList.remove(
        "visible"
    );

    selectedEvidence = null;

    confirmImportButton.disabled = true;
}

function renderEvidenceList(
    evidence
) {

    if (evidence.length === 0) {

        evidenceList.innerHTML = `
            <div class="subtitle">
                No evidence snapshots found.
            </div>
        `;

        return;
    }


    evidenceList.innerHTML = "";


    evidence.forEach(
        snapshot => {

            const element =
                document.createElement(
                    "div"
                );


            element.className =
                "evidence-item";


            element.dataset.name =
                snapshot.name;


            element.innerHTML = `

                <div>

                    <div class="process-name">
                        ${escapeHtml(
                            snapshot.name
                        )}
                    </div>

                    <div class="user">
                        Endpoint snapshot
                    </div>

                </div>

            `;


            element.addEventListener(
                "click",
                () => {

                    document
                        .querySelectorAll(
                            ".evidence-item"
                        )
                        .forEach(
                            item =>
                                item.classList.remove(
                                    "selected"
                                )
                        );


                    element.classList.add(
                        "selected"
                    );


                    selectedEvidence =
                        snapshot.name;


                    confirmImportButton.disabled =
                        false;
                }
            );


            evidenceList.appendChild(
                element
            );
        }
    );
}

confirmImportButton.addEventListener(
    "click",
    importSelectedEvidence
);


async function importSelectedEvidence() {

    if (!selectedEvidence) {
        return;
    }


    confirmImportButton.disabled =
        true;


    try {

        const response =
            await fetch(
                `/api/evidence/${encodeURIComponent(
                    selectedEvidence
                )}`,
                {
                    method: "POST"
                }
            );


        if (!response.ok) {

            const error =
                await response.json();

            throw new Error(
                error.detail ||
                "Failed to import evidence"
            );
        }


        closeEvidenceModal();


        await loadProcesses();


    } catch (error) {

        console.error(error);

        alert(
            "Failed to import evidence:\n\n" +
            error.message
        );


        confirmImportButton.disabled =
            false;
    }
}

/* =========================
   Status
========================= */


async function updateStatus() {

    try {

        const response =
            await fetch(
                "/api/status"
            );


        const status =
            await response.json();


        updateProgress(
            status.stage,
            status.progress
        );


        if (
            status.status ===
            "complete"
        ) {

            clearInterval(
                pollingInterval
            );


            analyzeButton.disabled =
                false;


            await loadProcesses();
        }


        if (
            status.status ===
            "error"
        ) {

            clearInterval(
                pollingInterval
            );


            analyzeButton.disabled =
                false;


            alert(
                "Analysis failed:\n\n" +
                status.error
            );
        }


    } catch (error) {

        console.error(error);
    }
}


function updateProgress(
    stage,
    percentage
) {

    progressStage.textContent =
        stage;


    progressPercent.textContent =
        percentage + "%";


    progress.style.width =
        percentage + "%";
}


/* =========================
   Processes
========================= */


async function loadProcesses() {

    const response =
        await fetch(
            "/api/processes"
        );


    if (!response.ok) {
        return;
    }


    const data =
        await response.json();


    document.getElementById(
        "processCount"
    ).textContent =
        data.processes.length;


    document.getElementById(
        "executableCount"
    ).textContent =
        data.executable_count;


    const snapshotTime =
        document.getElementById(
            "snapshotTime"
        );


    if (data.captured_at) {

        snapshotTime.textContent =
            new Date(
                data.captured_at
            ).toLocaleString();

    } else {

        snapshotTime.textContent =
            "Unknown";
    }


    const list =
        document.getElementById(
            "processList"
        );


    list.innerHTML = "";


    data.processes.forEach(
        process => {

            const element =
                document.createElement(
                    "div"
                );


            element.className =
                "process";


            element.dataset.pid =
                process.pid;


            element.innerHTML = `

                <div class="pid">
                    ${process.pid}
                </div>

                <div>

                    <div class="process-name">
                        ${escapeHtml(
                            process.name ||
                            "Unknown"
                        )}
                    </div>

                    <div class="user">
                        ${escapeHtml(
                            process.path ||
                            "No executable path"
                        )}
                    </div>

                </div>

                <div class="user">

                    ${escapeHtml(
                        process.username ||
                        "Unknown"
                    )}

                </div>

            `;


            element.addEventListener(
                "click",
                () =>
                    showProcessDetails(
                        process.pid
                    )
            );


            list.appendChild(
                element
            );
        }
    );
}


/* =========================
   Process details
========================= */


async function showProcessDetails(
    pid
) {

    const response =
        await fetch(
            `/api/processes/${pid}`
        );


    if (!response.ok) {
        return;
    }


    const data =
        await response.json();


    document
        .querySelectorAll(
            ".process-details-inline"
        )
        .forEach(
            element =>
                element.remove()
        );


    document
        .querySelectorAll(
            ".process"
        )
        .forEach(
            element =>
                element.classList.remove(
                    "selected"
                )
        );


    const processElement =
        document.querySelector(
            `.process[data-pid="${pid}"]`
        );


    if (!processElement) {
        return;
    }


    processElement.classList.add(
        "selected"
    );


    const detailElement =
        document.createElement(
            "div"
        );


    detailElement.className =
        "process-details-inline";


    detailElement.innerHTML =
        renderProcessDetails(
            data
        );


    processElement.after(
        detailElement
    );
}


/* =========================
   Process details renderer
========================= */


function renderProcessDetails(
    data
) {

    const process =
        data.process;


    return `

        <div class="detail-section">

            <h3>
                Process
            </h3>


            ${detailRow(
                "Name",
                escapeHtml(
                    process.name ||
                    "Unknown"
                )
            )}


            ${detailRow(
                "PID",
                process.pid
            )}


            ${detailRow(
                "Parent PID",
                process.parent_pid
            )}


            ${detailRow(
                "User",
                escapeHtml(
                    process.username ||
                    "Unknown"
                )
            )}


            ${detailRow(
                "Executable",
                escapeHtml(
                    process.path ||
                    "Unknown"
                )
            )}


            ${detailRow(
                "Created",
                process.create_time
            )}


            ${detailRow(
                "Observed at",
                escapeHtml(
                    process.observed_at ||
                    "Unknown"
                )
            )}

        </div>


        <div class="detail-section">

            <h3>
                Command Line
            </h3>


            <pre class="command-line"><code>${escapeHtml(
                formatCommandLine(
                    process.command_line
                )
            )}</code></pre>

        </div>


        <div class="detail-section">

            <h3>
                Parent
            </h3>


            ${
                data.parent

                ? renderFollowProcess(
                    data.parent
                )

                : `
                    <div class="subtitle">
                        Parent not present in snapshot.
                    </div>
                `
            }

        </div>


        <div class="detail-section">

            <h3>
                Children
            </h3>


            ${
                data.children.length > 0

                ? data.children
                    .map(
                        child =>
                            renderFollowProcess(
                                child
                            )
                    )
                    .join("")

                : `
                    <div class="subtitle">
                        No child processes.
                    </div>
                `
            }

        </div>


        <div class="detail-section">

            <h3>
                Executable Intelligence
            </h3>


            ${
                data.executable

                ? renderExecutable(
                    data.executable
                )

                : `
                    <div class="subtitle">
                        No executable metadata available.
                    </div>
                `
            }

        </div>

    `;
}


/* =========================
   Follow
========================= */


function renderFollowProcess(
    process
) {

    return `

        <div class="related-process">

            <div>

                <div class="process-name">

                    ${escapeHtml(
                        process.name ||
                        "Unknown"
                    )}

                </div>

                <div class="user">

                    PID ${process.pid}

                </div>

            </div>


            <button
                class="follow-button"
                onclick="followProcess(${process.pid})"
            >
                Follow →
            </button>

        </div>

    `;
}


async function followProcess(
    pid
) {

    await showProcessDetails(
        pid
    );


    const element =
        document.querySelector(
            `.process[data-pid="${pid}"]`
        );


    if (element) {

        element.scrollIntoView({
            behavior: "smooth",
            block: "center"
        });

    }
}


/* =========================
   Executable
========================= */


function renderExecutable(
    executable
) {

    const pe =
        executable.pe;


    return `

        ${detailRow(
            "File",
            escapeHtml(
                executable.name ||
                "Unknown"
            )
        )}


        ${detailRow(
            "Path",
            escapeHtml(
                executable.path ||
                "Unknown"
            )
        )}


        ${detailRow(
            "SHA-256",
            escapeHtml(
                executable.sha256 ||
                "Unavailable"
            )
        )}


        ${detailRow(
            "Size",
            `${executable.size} bytes`
        )}


        ${detailRow(
            "Created",
            executable.created_time
        )}


        ${detailRow(
            "Modified",
            executable.modified_time
        )}


        ${
            pe

            ? `

                ${detailRow(
                    "Architecture",
                    escapeHtml(
                        pe.architecture
                    )
                )}


                ${detailRow(
                    "Subsystem",
                    escapeHtml(
                        pe.subsystem
                    )
                )}


                ${detailRow(
                    "Entry Point",
                    escapeHtml(
                        pe.entry_point
                    )
                )}


                ${detailRow(
                    "Image Base",
                    escapeHtml(
                        pe.image_base
                    )
                )}

            `

            : `
                <div class="subtitle">
                    PE analysis unavailable.
                </div>
            `
        }

    `;
}


/* =========================
   Helpers
========================= */


function detailRow(
    label,
    value
) {

    return `

        <div class="detail-row">

            <div class="detail-label">
                ${label}
            </div>

            <div class="detail-value">
                ${value}
            </div>

        </div>

    `;
}


function formatCommandLine(
    commandLine
) {

    if (!commandLine) {

        return "No command line available";
    }


    if (Array.isArray(commandLine)) {

        return commandLine
            .map(
                argument =>
                    `"${argument}"`
            )
            .join(" ");

    }


    return String(
        commandLine
    );
}


function escapeHtml(
    value
) {

    if (
        value === null ||
        value === undefined
    ) {

        return "";
    }


    return String(value)

        .replaceAll(
            "&",
            "&amp;"
        )

        .replaceAll(
            "<",
            "&lt;"
        )

        .replaceAll(
            ">",
            "&gt;"
        )

        .replaceAll(
            '"',
            "&quot;"
        )

        .replaceAll(
            "'",
            "&#039;"
        );
}

document.addEventListener(
    "DOMContentLoaded",
    async () => {

        try {

            const response =
                await fetch(
                    "/api/status"
                );

            if (!response.ok) {
                return;
            }

            const status =
                await response.json();


            updateProgress(
                status.stage,
                status.progress
            );


            if (
                status.status ===
                "complete"
            ) {

                analyzeButton.disabled =
                    false;

                await loadProcesses();
            }


        } catch (error) {

            console.error(
                "Failed to restore previous analysis:",
                error
            );
        }
    }
);