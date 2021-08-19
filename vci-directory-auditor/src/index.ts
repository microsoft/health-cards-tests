// Audit script for the VCI issuers directory

import { Command } from 'commander';
import { JWK } from "node-jose";
import got from 'got';
import fs from 'fs';
import path from 'path';
import date from 'date-and-time';

const VCI_ISSUERS_DIR_URL = "https://raw.githubusercontent.com/the-commons-project/vci-directory/main/vci-issuers.json";

//
// interfaces
//

interface TrustedIssuer {
    iss: string,
    name: string
}

interface TrustedIssuers {
    participating_issuers: TrustedIssuer[]
}

interface IssuerLogInfo {
    issuer: TrustedIssuer,
    keys: JWK.Key[],
    errors?: string[]
}

interface IssuerKids {
    iss: string,
    kids: string[]
}

interface DirectoryLog {
    directory: string,
    time: string,
    issuerInfo: IssuerLogInfo[]
}

interface AuditLog {
    directory: string,
    time: string,
    issuerCount: number,
    newIssuerCount?: number,
    deletedIssuerCount?: number,
    issuersWithErrors: IssuerLogInfo[],
    duplicatedKids: string[],
    duplicatedIss: string[],    
    duplicatedNames: string[],
    removedKids?: IssuerKids[]
}

interface KeySet {
    keys : JWK.Key[]
}

interface Options {
    directorylog: string;
    previous: string;
    auditlog: string;
    directory: string;
    test: boolean
}

//
// program options
//
const program = new Command();
program.option('-l, --directorylog <directorylog>', 'output log file storing directory issuer keys');
program.option('-p, --previous <previous>', 'directory log file from a previous audit');
program.option('-a, --auditlog <auditlog>', 'output audit file on the directory');
program.option('-d, --directory <directory>', 'URL of the directory to audit; uses the VCI one by default');
program.option('-t, --test', 'test mode');
program.parse(process.argv);
const currentTime = new Date();

// process options
const options = program.opts() as Options;
if (!options.directory) {
    // use VCI directory by default
    options.directory = VCI_ISSUERS_DIR_URL;
}
if (!options.directorylog) {
    // default directory log name
    options.directorylog = path.join('logs', `directory_log_${date.format(currentTime, 'YYYY-MM-DD-HHmmss')}.json`);
}
if (!options.auditlog) {
    // default audit log name
    options.auditlog = path.join('logs', `audit_log_${date.format(currentTime, 'YYYY-MM-DD-HHmmss')}.json`);
}

// download the specified directory
async function fetchDirectory(directoryUrl: string) : Promise<DirectoryLog> {
    const response = await got(directoryUrl, { timeout: 5000 });
    if (!response) {
        Promise.reject("Can't connect to directory");
    }

    const issuers = JSON.parse(response.body) as TrustedIssuers;
    if (!issuers) {
        Promise.reject("Can't parse issuer directory");
    }

    const issuerLogInfo = issuers.participating_issuers.map(async (issuer): Promise<IssuerLogInfo> => {
        const jwkURL = issuer.iss + '/.well-known/jwks.json';
        const issuerLogInfo: IssuerLogInfo = {
            issuer: issuer,
            keys: [],
            errors: []
        }
        try {
            const response = await got(jwkURL, { timeout:5000 });
            if (!response) {
                throw "Can't reach JWK URL";
            }
            const keySet = JSON.parse(response.body) as KeySet;
            if (!keySet) {
                throw "Failed to parse JSON KeySet schema";
            }
            issuerLogInfo.keys = keySet.keys; 
        } catch (err) {
            issuerLogInfo.errors?.push((err as Error).toString());
        }
        return issuerLogInfo;        
    });

    const directoryLog: DirectoryLog = {
        directory: directoryUrl,
        time: date.format(currentTime, 'YYYY-MM-DD HH:mm:ss'),
        issuerInfo: []    
    }
    try {
        directoryLog.issuerInfo = await Promise.all(issuerLogInfo);
    } catch(err) {
        Promise.reject(err);
    }

    return directoryLog;
}

// get duplicates in a string array
function getDuplicates(array: string[]) : string[] {
    const set = new Set(array);
    const duplicates = array.filter(item => {
        if (set.has(item)) {
            set.delete(item);
        } else {
            return item;
        }
    });
    return Array.from(new Set(duplicates));
}

// audit the directory, optionaly comparing it to a previously obtained directory
// TODO: check the key sets cryptographically
function audit(isTest: boolean, currentLog: DirectoryLog, previousLog: DirectoryLog | undefined) : AuditLog {
    // get the issuer URL. If using our test files, replace "audit-*" with "audit" (we iterate on the audit folder name
    // to simulate changes over time)
    const getIssuerUrl = (iss: string) => isTest ? iss.replace(/audit-\d/,'audit') : iss;
    // get the issuers from a directory log
    const getIssuers = (dir: DirectoryLog) => dir.issuerInfo.map(info => getIssuerUrl(info.issuer.iss));
    const currentIss = getIssuers(currentLog);
    const auditLog: AuditLog = {
        directory: currentLog.directory,
        time: currentLog.time,
        issuerCount: currentLog.issuerInfo.length,
        issuersWithErrors: currentLog.issuerInfo.filter(info => info.errors != undefined && info.errors.length > 0),
        duplicatedKids: getDuplicates(currentLog.issuerInfo.flatMap(info => info.keys.map(key => key.kid))),
        duplicatedIss: getDuplicates(currentIss),
        duplicatedNames: getDuplicates(currentLog.issuerInfo.map(info => info.issuer.name))
    }
    if (previousLog) {
        const initialCount = 0;
        const previousIss = getIssuers(previousLog);
        auditLog.newIssuerCount = currentIss.reduce((acc, current) => acc + (previousIss.includes(current) ? 0 : 1), initialCount);
        auditLog.deletedIssuerCount = previousIss.reduce((acc, current) => acc + (currentIss.includes(current) ? 0 : 1), initialCount);
        const getIssuerKids = (dir: DirectoryLog) => dir.issuerInfo.map(info => { return { iss: getIssuerUrl(info.issuer.iss), kids: info.keys.map(key => key.kid)}});
        const currentIssKids: IssuerKids[] = getIssuerKids(currentLog);
        const previousIssKids: IssuerKids[] = getIssuerKids(previousLog);
        auditLog.removedKids = [];
        previousIssKids.forEach(pik => {
            currentIssKids.forEach(cik => {
                if (pik.iss === cik.iss) {
                    const removedKids: string[] = [];
                    pik.kids.forEach(kid => {
                        if (!cik.kids.includes(kid)) {
                            removedKids.push(kid);
                        }
                    })
                    if (removedKids.length > 0) {
                        auditLog.removedKids?.push({iss: pik.iss, kids: removedKids});
                    }
                }
            })
        });
    }
    
    return auditLog;
}


// main
void (async () => {
    console.log(`Auditing ${options.directory}`);
    try {
        const directoryLog = await fetchDirectory(options.directory);
        fs.writeFileSync(options.directorylog, JSON.stringify(directoryLog, null, 4));
        console.log(`Directory log written to ${options.directorylog}`);

        let previousDirectoryLog: DirectoryLog | undefined = undefined;
        if (options.previous) {
            let errMsg = `Can't read ${options.previous}`;
            try {
                previousDirectoryLog = JSON.parse(fs.readFileSync(options.previous).toString('utf-8')) as DirectoryLog;
            } catch (e) {
                errMsg += (". " + (e as Error).message);
            }
            if (!previousDirectoryLog) {
                console.log(errMsg);
            }
        }

        const auditLog = audit(options.test, directoryLog, previousDirectoryLog);
        fs.writeFileSync(options.auditlog, JSON.stringify(auditLog, null, 4));
        console.log(`Audit log written to ${options.auditlog}`);
    } catch (err) {
        console.log(err);
    }
})();