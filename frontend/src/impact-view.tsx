import {PagedTable} from './pagination';
import {useI18n} from './i18n';
type DecisionSummary={decision:'allow'|'deny';matched_policy:string|null;policy_version:string;explanation:string};
export type Impact={baseline_version:string;candidate_version:string;total:number;newly_allowed:number[];newly_denied:number[];unchanged:number;coverage:string;comparisons:{index:number;baseline:DecisionSummary;candidate:DecisionSummary;effect:string}[]};
export function ImpactView({impact}:{impact:Impact}) {
  const {t}=useI18n();

  return <div className="impact-report"><h3>{t("Sampled change impact")}</h3>
    <p>{t("Baseline:")} {impact.baseline_version}<br/>{t("Candidate:")} {impact.candidate_version}</p>
    <p>{impact.total}  {t("samples ·")} {impact.newly_allowed.length}  {t("newly allowed ·")} {impact.newly_denied.length}  {t("newly denied ·")} {impact.unchanged}  {t("unchanged")}</p>
    <p className="notice">{t("Coverage:")} {t(impact.coverage)}{t(". Risk, required MFA and obligations are not assessed. This report is not approval evidence and does not change production policy.")}</p>
    <div className="table-scroll"><PagedTable><caption>{t("Decisions for the submitted sample snapshot")}</caption><thead><tr><th>{t("Sample")}</th><th>{t("Baseline")}</th><th>{t("Candidate")}</th><th>{t("Effect")}</th></tr></thead><tbody>{impact.comparisons.map(item=><tr key={item.index}><td>{item.index+1}</td><td>{t(item.baseline.decision)}<br/><small>{item.baseline.matched_policy||t("No matched rule")}</small></td><td>{t(item.candidate.decision)}<br/><small>{item.candidate.matched_policy||t("No matched rule")}</small></td><td>{t(item.effect)}</td></tr>)}</tbody></PagedTable></div>
  </div>;
}
