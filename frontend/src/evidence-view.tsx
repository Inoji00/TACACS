import {PagedTable,PageButtons} from './pagination';
import {useI18n} from './i18n';
import {ImpactView,type Impact} from './impact-view';

export type EvidenceSummary={report_id:string;simulated_by:string;created_at:string;candidate_version:string;baseline_version:string;sample_count:number;integrity_status:string};
export type EvidencePage={items:EvidenceSummary[];next_before:string|null};
export type EvidenceRecord=EvidenceSummary&{baseline_rules_digest:string;candidate_rules_digest:string;samples_digest:string;report:Impact};
export type ReplayResult={report_id:string;candidate_version:string;baseline_version:string;samples_match:boolean;rules_match:boolean;decisions_match:boolean|null;integrity_status:string;coverage:string};

export function EvidenceView({version,page,record,busy,onRefresh,onOlder,pageNumber=1,lastPage=1,onPage,onInspect,onClear,replay=null,onReplay}:{version:string;page:EvidencePage|null;record:EvidenceRecord|null;busy:boolean;onRefresh:()=>void;onOlder:()=>void;pageNumber?:number;lastPage?:number;onPage?:(number:number)=>void;onInspect:(id:string)=>void;onClear:()=>void;replay?:ReplayResult|null;onReplay?:()=>void}) {
  const {t}=useI18n();

  return <section className="card evidence"><h2>{t("Saved simulation evidence")}</h2>
    <p>{t("Browse immutable reports for the selected policy version. These are historical snapshots, not results for the current form inputs.")}</p>
    <p className="notice">{t("Viewing a stored report or digest does not verify audit-chain integrity, signature, sample provenance or exhaustive coverage.")}</p>
    <div className="actions"><button disabled={busy||!version} onClick={onRefresh}>{t("Load saved reports")}</button>{!onPage&&page?.next_before&&<button className="secondary" disabled={busy} onClick={onOlder}>{t("Older reports")}</button>}</div>
    {page&&(!page.items.length?<p>{t("No saved reports found for this policy version.")}</p>:<div className="table-scroll"><PagedTable><caption>{t("Saved snapshots · newest first")}</caption><thead><tr><th>{t("Created")}</th><th>{t("Actor")}</th><th>{t("Samples")}</th><th>{t("Report")}</th></tr></thead><tbody>{page.items.map(item=><tr key={item.report_id}><td>{item.created_at}</td><td>{item.simulated_by}</td><td>{item.sample_count}</td><td><button className="secondary" disabled={busy} aria-label={`${t("Open report")} ${item.report_id}`} onClick={()=>onInspect(item.report_id)}>{t("Open report")}</button><br/><small>{item.report_id}</small></td></tr>)}</tbody></PagedTable></div>)}
    {page&&onPage&&<PageButtons page={pageNumber} last={lastPage} onPage={onPage} busy={busy}/>}
    {record&&<div className="evidence-detail"><h3>{t("Stored report")}</h3><p>{t("Report ID:")} <code>{record.report_id}</code><br/>{t("Created:")} {record.created_at}<br/>{t("Actor:")} {record.simulated_by}<br/>{t("Integrity status:")} {t(record.integrity_status)}</p><button className="secondary" disabled={busy} onClick={onClear}>{t("Close stored report")}</button>
      <details><summary>{t("Snapshot digests")}</summary><dl><dt>{t("Baseline rules SHA-256")}</dt><dd><code>{record.baseline_rules_digest}</code></dd><dt>{t("Candidate rules SHA-256")}</dt><dd><code>{record.candidate_rules_digest}</code></dd><dt>{t("Original samples SHA-256")}</dt><dd><code>{record.samples_digest}</code></dd></dl><p className="hint">{t("Raw samples are not stored here. Replaying requires the exact original input set and a separate verification workflow.")}</p></details>
      <ImpactView impact={record.report}/>
      {onReplay&&<button className="secondary" disabled={busy} onClick={onReplay}>{t("Replay against current samples")}</button>}
      <p className="hint">{t("Replay uses the recorded baseline and candidate versions, not the current active policy. Use the exact original samples in the test-case editor. Expected results are ignored.")}</p>
      {replay&&replay.report_id===record.report_id&&<section aria-label={t("Replay verification result")}><h3>{t("Replay verification")}</h3><dl><dt>{t("Original samples")}</dt><dd>{replay.samples_match?t("Match"):t("Do not match")}</dd><dt>{t("Recorded rules")}</dt><dd>{replay.rules_match?t("Match"):t("Do not match or unavailable")}</dd><dt>{t("Recorded decisions")}</dt><dd>{replay.decisions_match===null?t("Not evaluated"):replay.decisions_match?t("Match"):t("Do not match")}</dd></dl><p className="notice">{t("Integrity status:")} {t(replay.integrity_status)}{t(". Replay matching does not verify provenance, signatures or audit-chain integrity. Coverage:")} {t(replay.coverage)}.</p></section>}
    </div>}
  </section>;
}
