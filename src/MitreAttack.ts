import fs from "fs";
import {
    SubTechnique,
    Table,
    Technique,
} from "./dataTypes";
import axios from "axios";

interface siemData {
    data: any[]
}

export class MitreAttack {
    domain: string;
    siemData: siemData;
    resultTable: any[] = [];
    tacticConfig: string[];
    techniqueConfig: string[];

    constructor(
        domain: string,
        tacticConfig: string[] = [
            "name",
            "type",
            "x_mitre_shortname",
            "external_references",
        ],
        techniqueConfig: string[] = [
            "name",
            "type",
            "external_references",
            "kill_chain_phases",
        ],
        siemData: any = {data: []},
    ) {
        this.domain = domain;
        this.siemData = siemData;
        this.tacticConfig = tacticConfig;
        this.techniqueConfig = techniqueConfig;
    }

    #goToRootDirectory = () => {
        let correctDirectory = process.cwd().split("\\");
        while (correctDirectory[correctDirectory.length - 1] !== "server") {
            process.chdir("..");
            correctDirectory = process.cwd().split("\\");
        }
    };

    checkFileRelevant = (fileName: string, data: any) => {
        // Change the directory to add our file to the correct directory
        this.#goToRootDirectory();
        process.chdir(`./data/${this.domain}`);

        if (fs.existsSync(fileName)) {
            let dataRes = JSON.stringify(
                JSON.parse(fs.readFileSync(fileName, "utf8")),
            );
            if (dataRes === data) {
                console.log(`${fileName.toUpperCase()}: data is relevant`);
            } else {
                console.warn(`${fileName.toUpperCase()}: data is updating`);
                try {
                    fs.writeFileSync(fileName, data);
                    console.log(`${fileName.toUpperCase()}: data updated`);
                } catch (err) {
                    console.error(err);
                }
            }
        } else {
            try {
                fs.writeFileSync(fileName, data);
                console.log(`${fileName.toUpperCase}: file creation completed`);
            } catch (err) {
                console.error(err);
            }
        }

        this.#goToRootDirectory();
    };

    #sortBySubName = (first: any, second: any) => {
        if (first.external_id < second.external_id) {
            return -1;
        } else if (first.external_id > second.external_id) {
            return 1;
        } else {
            return 0;
        }
    };

    #sortByName = (first: any, second: any) => {
        if (first.name < second.name) {
            return -1;
        } else if (first.name > second.name) {
            return 1;
        } else {
            return 0;
        }
    };

    getTypeData = async (type: string, jsonConfig?: string[]) => {
        try {
            // Get full table
            let table = await axios.get(
                `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/${this.domain}/${this.domain}.json`,
            );

            // Main table is in data objects
            let data = await JSON.parse(JSON.stringify(table.data["objects"]));

            // This array will be our json file
            let resArr = [];

            // This loop adds a user data type inside the json element
            for (const i of data) {
                if (i.type === type) {
                    if (
                        i.hasOwnProperty("revoked") ||
                        i.hasOwnProperty("x_mitre_deprecated")
                    ) {
                        if (i.revoked === true) {
                            continue;
                        }
                        if (i.x_mitre_deprecated === true) {
                            continue;
                        }
                    }

                    // Json element
                    let tactic: any = {};

                    for await (const value of jsonConfig || ["name", "type"]) {
                        // We use only first element, because we don't need the others
                        if (value === "external_references") {
                            tactic[value] = i[value][0];
                        } else {
                            tactic[value] = i[value];
                        }
                    }
                    // Json element add to our future file
                    resArr.push(tactic);
                }
            }

            // Convert the array to Json format
            return resArr;
        } catch (err) {
            console.error(err);
        }
    };

    getTechniques = async () => {
        let dataTech =
            (await this.getTypeData("attack-pattern", this.techniqueConfig)) || [];

        if (dataTech.length === 0) {
            throw "data isn't fetched";
        }

        // Array of sub techniques
        let subTechniquesArr: SubTechnique[] = [];

        // Array of techniques
        let techniquesArr = [];

        for (const technique of dataTech) {
            // Splitting external id to check the type of tech (sub or main)
            let externalId = technique.external_references.external_id.split(".");

            // If the length is 2 - it's a sub technique
            if (externalId.length === 2) {
                let subEl: SubTechnique = {
                    name: technique.name,
                    siem_exist: "none",
                    external_main_id: externalId[0],
                    external_id: externalId[1],
                    external_url: technique.external_references.url,
                    kill_chain_phase: technique.kill_chain_phases,
                };

                if (this.siemData !== undefined) {
                    //
                    for (const siemEl of this.siemData.data) {
                        if (
                            siemEl[siemEl.length - 1].includes(
                                technique.external_references.external_id,
                            )
                        ) {
                            subEl.siem_exist = "var(--fully-covers)";
                            break;
                        }
                    }
                }

                // Adding our sub technique to the array
                subTechniquesArr.push(subEl);
            } else {
                let resArrObj: Technique = {
                    name: technique.name,
                    siem_exist: "none",
                    siem_exist_count: 0,
                    external_id: technique.external_references.external_id,
                    external_url: technique.external_references.url,
                    kill_chain_phase: technique.kill_chain_phases,
                    sub_techniques: [],
                };

                if (this.siemData !== undefined) {
                    //
                    for (const siemEl of this.siemData.data) {
                        if (
                            siemEl[siemEl.length - 1].includes(
                                technique.external_references.external_id,
                            )
                        ) {
                            resArrObj.siem_exist = "var(--fully-covers)";
                        }
                    }
                }

                // Adding our main technique to the array
                techniquesArr.push(resArrObj);
            }
        }

        // Searching main technique for sub technique
        for (const mainTech of techniquesArr) {
            let counter = 0;
            // It's array will decrease after finding the main technique
            let updatedSubTechArr = [];

            for (const subEl of subTechniquesArr) {
                // If main id is equal -> add the sub technique to the main technique
                if (subEl.external_main_id === mainTech.external_id) {
                    mainTech.sub_techniques.push(subEl);

                    if (this.siemData) {
                        //
                        if (subEl.siem_exist === "var(--fully-covers)") {
                            counter += 1;
                        }
                    }
                } else {
                    updatedSubTechArr.push(subEl);
                }
            }
            // Update the array to the updated version
            subTechniquesArr = updatedSubTechArr;
            mainTech.sub_techniques.sort(this.#sortBySubName);
            if (this.siemData) {
                mainTech.siem_exist_count = counter || 0;

                //
                if (
                    mainTech.sub_techniques.length > 1 &&
                    counter > 0 &&
                    mainTech.sub_techniques.length != counter
                ) {
                    mainTech.siem_exist = "var(--partially-covers)";
                } else if (
                    mainTech.siem_exist === "var(--fully-covers)" &&
                    counter === 0
                ) {
                    mainTech.siem_exist = "var(--partially-covers)";
                }
            }
        }

        return techniquesArr;
    };
    getDomainTable = async () => {
        // Getting an array with all techniques
        let fullTech = await this.getTechniques();

        let dataTactics =
            (await this.getTypeData("x-mitre-tactic", this.tacticConfig)) || [];

        if (dataTactics.length === 0) {
            throw "data isn't fetched";
        }

        // Our output data
        let fileArr = [];

        // Array with the correct position of tactics (from left to right)
        const correctPosition = [
            "TA0043",
            "TA0042",
            "TA0001",
            "TA0002",
            "TA0003",
            "TA0004",
            "TA0005",
            "TA0006",
            "TA0007",
            "TA0008",
            "TA0009",
            "TA0011",
            "TA0010",
            "TA0040",
        ];

        // Creating an array with all tactics
        for (const position of correctPosition) {
            for (const tactic of dataTactics) {
                if (position === tactic.external_references.external_id) {
                    const resObj: Table = {
                        name: tactic.name,
                        x_mitre_shortname: tactic.x_mitre_shortname,
                        external_id: tactic.external_references.external_id,
                        external_url: tactic.external_references.url,
                        techniques: [],
                    };
                    fileArr.push(resObj);
                    break;
                }
            }
        }

        for (const tactic of fileArr) {
            // A Set with unique techniques that don't fit our tactic
            let techArr: any = new Set();

            for (const tech of fullTech) {
                for (const chainPhase of tech.kill_chain_phase) {
                    if (chainPhase.phase_name === tactic.x_mitre_shortname) {
                        tactic.techniques.push(tech);
                    } else {
                        techArr.add(tech);
                    }
                }
            }
            tactic.techniques.sort(this.#sortByName);
            fullTech = Array.from(techArr);
        }

        if (this.resultTable.length === 0) {
            this.resultTable = fileArr;
            return fileArr;
        } else {
            return fileArr;
        }
    };
}

