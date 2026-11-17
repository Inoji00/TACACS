"""Validate persisted sampled reports before returning them to the console.

Database JSON is not a safe response schema by itself. Fail closed on extra
fields (including raw samples), inconsistent decisions or unknown assessments.
This is structural validation, not cryptographic provenance verification.
"""


def validate_report(report, *, baseline_version, candidate_version, sample_count):
    def invalid():
        raise RuntimeError('simulation evidence unavailable')

    def indexes(value):
        if not isinstance(value,(list,tuple)) or len(value)>sample_count:
            invalid()
        if any(type(index) is not int or not 0<=index<sample_count for index in value):
            invalid()
        if list(value)!=sorted(set(value)):
            invalid()
        return tuple(value)

    def decision(value,version):
        fields={'decision','matched_policy','policy_version','explanation','required_mfa','risk','obligations'}
        if not isinstance(value,dict) or set(value)!=fields:
            invalid()
        if (value['decision'] not in ('allow','deny') or value['policy_version']!=version
                or value['required_mfa'] is not None or value['risk']!='unassessed'
                or value['obligations'] is not None):
            invalid()
        matched=value['matched_policy']
        if matched is not None and (not isinstance(matched,str) or not 1<=len(matched)<=65536):
            invalid()
        explanation=value['explanation']
        if explanation not in ('matched policy rule','no policy rule matched','invalid command'):
            invalid()
        if (explanation=='matched policy rule')!=(matched is not None):
            invalid()
        if value['decision']=='allow' and matched is None:
            invalid()
        return value['decision']

    if type(sample_count) is not int or not 1<=sample_count<=1024:
        invalid()
    fields={'baseline_version','candidate_version','total','newly_allowed','newly_denied',
            'unchanged','comparisons','coverage'}
    if not isinstance(report,dict) or set(report)!=fields:
        invalid()
    if (report['baseline_version']!=baseline_version or report['candidate_version']!=candidate_version
            or type(report['total']) is not int or report['total']!=sample_count
            or report['coverage']!='provided-samples-only'):
        invalid()
    comparisons=report['comparisons']
    if not isinstance(comparisons,(list,tuple)) or len(comparisons)!=sample_count:
        invalid()
    allowed,denied=[],[]
    for index,item in enumerate(comparisons):
        if not isinstance(item,dict) or set(item)!={'index','baseline','candidate','effect'}:
            invalid()
        if type(item['index']) is not int or item['index']!=index:
            invalid()
        before=decision(item['baseline'],baseline_version)
        after=decision(item['candidate'],candidate_version)
        if before=='deny' and after=='allow':
            effect='newly-allowed';allowed.append(index)
        elif before=='allow' and after=='deny':
            effect='newly-denied';denied.append(index)
        else:
            effect='unchanged'
        if item['effect']!=effect:
            invalid()
    if (indexes(report['newly_allowed'])!=tuple(allowed) or indexes(report['newly_denied'])!=tuple(denied)
            or type(report['unchanged']) is not int
            or report['unchanged']!=sample_count-len(allowed)-len(denied)):
        invalid()
    return report
