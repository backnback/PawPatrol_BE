import re
from collections import defaultdict
from datetime import datetime
import os
import argparse
import json
from typing import List, Dict, Any, Tuple


def analyze_multiple_apis(hibernate_log_path='logs/hibernate.log',
                          spy_log_path='logs/spy.log',
                          warmup_count=1,
                          min_calls_per_api=2,
                          debug=False):
    """
    여러 API 경로에 대한 성능 분석을 수행하고 N+1 문제가 많이 발생하는 경로를 식별합니다.

    Args:
        hibernate_log_path (str): Hibernate 로그 파일 경로
        spy_log_path (str): P6Spy 로그 파일 경로
        warmup_count (int): 각 API별 워밍업 호출로 간주할 초기 호출 횟수
        min_calls_per_api (int): 분석에 포함할 API의 최소 호출 횟수
        debug (bool): 디버깅 정보 출력 여부
    """
    # 파일 존재 확인
    for path in [hibernate_log_path, spy_log_path]:
        if not os.path.exists(path):
            print(f"오류: {path} 파일이 존재하지 않습니다.")
            return

    # 로그 파일 읽기
    try:
        with open(hibernate_log_path, 'r', encoding='utf-8') as f:
            hibernate_lines = f.readlines()

        with open(spy_log_path, 'r', encoding='utf-8') as f:
            spy_lines = f.readlines()

        if debug:
            print(f"Hibernate 로그: {len(hibernate_lines)} 라인, P6Spy 로그: {len(spy_lines)} 라인")
    except Exception as e:
        print(f"로그 파일 읽기 오류: {e}")
        return

    # 모든 API 호출 추출
    all_api_calls = extract_all_api_calls(hibernate_lines, debug)

    if not all_api_calls:
        print("로그에서 API 호출을 찾을 수 없습니다.")
        return

    # API 경로별로 호출 그룹화
    api_calls_by_path = group_calls_by_api_path(all_api_calls)

    print(f"총 {len(api_calls_by_path)}개의 API 경로를 발견했습니다.")

    # P6Spy 로그 분석
    connection_queries = extract_spy_queries(spy_lines, debug)

    # API 호출 결과 분석
    api_analysis_results = []

    for api_path, calls in api_calls_by_path.items():
        if len(calls) < min_calls_per_api:
            print(f"API 경로 '{api_path}'는 호출 횟수({len(calls)}회)가 최소 기준({min_calls_per_api}회)보다 적어 분석에서 제외됩니다.")
            continue

        print(f"API 경로 '{api_path}' 분석 중... (총 {len(calls)}회 호출)")

        # API 호출과 쿼리 매칭
        match_queries_to_api_calls(calls, connection_queries, debug)

        # 워밍업 호출과 분석 호출 분리
        warmup_count_for_api = min(warmup_count, len(calls) - 1)  # 최소 1개는 분석용으로 남겨둠

        if len(calls) <= warmup_count_for_api + 1:
            print(f"경고: API 경로 '{api_path}'는 분석에 충분한 호출이 없습니다.")
            warmup_calls = calls[:warmup_count_for_api]
            analysis_calls = calls[warmup_count_for_api:]
        else:
            warmup_calls = calls[:warmup_count_for_api]
            analysis_calls = calls[warmup_count_for_api:]

        # API별 분석 수행
        result = analyze_api_performance(api_path, analysis_calls, debug)
        api_analysis_results.append(result)

    # 결과를 N+1 문제 심각도에 따라 정렬
    api_analysis_results.sort(key=lambda x: x['n_plus_1_score'], reverse=True)

    # 종합 보고서 생성
    generate_summary_report(api_analysis_results)


def extract_all_api_calls(hibernate_lines, debug):
    """Hibernate 로그에서 모든 API 호출 정보 추출"""
    all_api_calls = []
    api_calls_found = 0

    # API 호출 시작과 종료를 나타내는 패턴
    start_pattern = re.compile(r'API 호출 시작: (GET|POST|PUT|DELETE) ([^\s]+)')
    end_pattern = re.compile(r'API 호출 완료: (GET|POST|PUT|DELETE) ([^\s]+).*실행시간: (\d+)ms')

    current_api_call = None

    for i, line in enumerate(hibernate_lines):
        # API 호출 시작 검사
        start_match = start_pattern.search(line)
        if start_match:
            method = start_match.group(1)
            path = start_match.group(2)

            # 가끔 경로에 ==========가 포함되어 있을 수 있어서 정리
            path = path.replace('=', '').strip()

            # 타임스탬프 추출
            timestamp = extract_timestamp(line, hibernate_lines, i, 5)

            current_api_call = {
                'method': method,
                'path': path,
                'start_time': timestamp,
                'start_line_idx': i,
                'hibernate_queries': []
            }

            api_calls_found += 1

            if debug and api_calls_found % 10 == 0:
                print(f"{api_calls_found}개 API 호출 발견...")

        # API 호출 종료 검사
        elif current_api_call and end_pattern.search(line):
            end_match = end_pattern.search(line)
            method = end_match.group(1)
            path = end_match.group(2)
            execution_time = int(end_match.group(3))

            # 가끔 경로에 ==========가 포함되어 있을 수 있어서 정리
            path = path.replace('=', '').strip()

            # 시작한 API와 종료된 API가 일치하는지 확인
            if current_api_call['method'] == method and current_api_call['path'] == path:
                # 타임스탬프 추출
                timestamp = extract_timestamp(line, hibernate_lines, i, 5)

                current_api_call['end_time'] = timestamp
                current_api_call['end_line_idx'] = i
                current_api_call['execution_time'] = execution_time

                # SQL 쿼리 추출
                for k in range(current_api_call['start_line_idx'] + 1, i):
                    if "org.hibernate.SQL" in hibernate_lines[k] and "Message:" in hibernate_lines[k]:
                        sql_match = re.search(r'Message: (.+)', hibernate_lines[k])
                        if sql_match:
                            sql = sql_match.group(1).strip()
                            sql_type = sql.split()[0].upper() if sql else "UNKNOWN"
                            current_api_call['hibernate_queries'].append({
                                'sql': sql,
                                'type': sql_type
                            })

                # 분석을 위해 spy_queries 필드 초기화
                current_api_call['spy_queries'] = []

                # 호출 정보 저장
                all_api_calls.append(current_api_call)
                current_api_call = None

    if debug:
        print(f"총 {api_calls_found}개 API 호출 중 {len(all_api_calls)}개 정보 추출 완료")

    return all_api_calls


def group_calls_by_api_path(api_calls):
    """API 경로별로 호출을 그룹화"""
    api_calls_by_path = defaultdict(list)

    for call in api_calls:
        # 메서드(GET/POST 등)와 경로를 함께 키로 사용
        key = f"{call['method']} {call['path']}"
        api_calls_by_path[key].append(call)

    return api_calls_by_path


def extract_timestamp(line, lines, line_idx, lookback=5):
    """로그 라인에서 타임스탬프 추출"""
    time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
    if time_match:
        return time_match.group(1)

    # 현재 라인에서 찾지 못한 경우 이전 라인 확인
    for i in range(max(0, line_idx-lookback), line_idx):
        time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', lines[i])
        if time_match:
            return time_match.group(1)

    return None


def extract_spy_queries(spy_lines, debug):
    """P6Spy 로그에서 쿼리 정보 추출"""
    connection_queries = defaultdict(list)
    query_count = 0

    for line in spy_lines:
        conn_match = re.search(r'connection (\d+)', line)
        if conn_match:
            conn_id = conn_match.group(1)

            # 타임스탬프 추출
            timestamp_match = re.search(r'^(\d+)', line)
            if timestamp_match:
                timestamp = int(timestamp_match.group(1))

                # 실행 시간 추출
                exec_time_match = re.search(r'\|(\d+)\|', line)
                exec_time = int(exec_time_match.group(1)) if exec_time_match else 0

                # SQL 쿼리 추출
                sql_types = ['select', 'insert', 'update', 'delete', 'create', 'alter', 'drop']
                for sql_type in sql_types:
                    sql_pattern = rf'\|{sql_type} .+\|{sql_type} .+'
                    sql_match = re.search(sql_pattern, line, re.IGNORECASE)
                    if sql_match:
                        query_count += 1
                        sql = sql_match.group(0).split('|', 1)[1].rsplit('|', 1)[0]

                        connection_queries[conn_id].append({
                            'timestamp': timestamp,
                            'execution_time': exec_time,
                            'sql': sql,
                            'type': sql_type.upper(),
                            'conn_id': conn_id
                        })
                        break

    if debug:
        print(f"P6Spy 로그에서 {len(connection_queries)}개 연결, {query_count}개 쿼리 추출")

    return connection_queries


def match_queries_to_api_calls(api_calls, connection_queries, debug):
    """API 호출과 P6Spy 쿼리 매칭"""
    if not api_calls or not connection_queries:
        return

    for i, api_call in enumerate(api_calls):
        # 타임스탬프 변환
        start_dt = datetime.strptime(api_call['start_time'], '%Y-%m-%d %H:%M:%S')
        end_dt = datetime.strptime(api_call['end_time'], '%Y-%m-%d %H:%M:%S')

        # 1초 여유 추가
        start_ts = int(start_dt.timestamp() * 1000)
        end_ts = int(end_dt.timestamp() * 1000) + 1000

        # 타임스탬프 기반 매칭
        conn_matches = {}
        for conn_id, queries in connection_queries.items():
            matched_queries = []
            for query in queries:
                ts = query['timestamp']
                if start_ts <= ts <= end_ts:
                    matched_queries.append(query)

            if matched_queries:
                conn_matches[conn_id] = len(matched_queries)
                api_call['spy_queries'].extend(matched_queries)

        if debug and i % 10 == 0:
            print(f"API 호출 #{i+1}: {len(api_call['spy_queries'])}개 쿼리 매칭됨")


def analyze_api_performance(api_path, api_calls, debug):
    """단일 API 경로에 대한 성능 분석 수행"""
    if not api_calls:
        return {
            'api_path': api_path,
            'calls_analyzed': 0,
            'n_plus_1_score': 0,
            'n_plus_1_likelihood': '없음',
            'avg_execution_time': 0,
            'avg_query_count': 0,
            'repeated_tables': [],
            'evidence': []
        }

    # 기본 통계
    total_exec_time = sum(call['execution_time'] for call in api_calls)
    avg_exec_time = total_exec_time / len(api_calls)

    total_hibernate_queries = sum(len(call['hibernate_queries']) for call in api_calls)
    avg_hibernate_queries = total_hibernate_queries / len(api_calls)

    total_spy_queries = sum(len(call['spy_queries']) for call in api_calls)
    avg_spy_queries = total_spy_queries / len(api_calls)

    # N+1 문제 분석
    n_plus_1_likelihood = "낮음"
    n_plus_1_score = 0  # N+1 문제 심각도 점수 (0-100)
    evidence = []

    # 첫 번째 N+1 지표: Hibernate와 P6Spy 쿼리 수 차이
    avg_query_ratio = avg_spy_queries / avg_hibernate_queries if avg_hibernate_queries > 0 else 0
    if avg_query_ratio > 2.0:
        n_plus_1_likelihood = "높음"
        n_plus_1_score += 30
        evidence.append(f"P6Spy/Hibernate 쿼리 비율: {avg_query_ratio:.1f} (> 2.0)")
    elif avg_query_ratio > 1.5:
        n_plus_1_likelihood = "중간"
        n_plus_1_score += 15
        evidence.append(f"P6Spy/Hibernate 쿼리 비율: {avg_query_ratio:.1f} (> 1.5)")

    # 두 번째 N+1 지표: 다수의 데이터베이스 연결 사용
    connections_per_call = []
    for call in api_calls:
        call_connections = set(q.get('conn_id', 'unknown') for q in call['spy_queries'])
        connections_per_call.append(len(call_connections))

        if len(call_connections) > 2:  # 하나의 API 호출에 2개 이상의 연결 사용
            n_plus_1_likelihood = "높음"
            n_plus_1_score += 20
            evidence.append(f"다중 연결 사용: {len(call_connections)}개의 연결")
            break

    # 평균 연결 수
    avg_connections = sum(connections_per_call) / len(connections_per_call) if connections_per_call else 0

    # 세 번째 N+1 지표: 특정 테이블에 대한 반복적인 SELECT 쿼리
    table_patterns = defaultdict(int)
    table_accesses_per_call = []

    for call in api_calls:
        call_tables = defaultdict(int)
        for query in call['spy_queries']:
            if query['type'] == 'SELECT':
                # 간단한 테이블 추출 (FROM 절 다음의 첫 단어)
                sql = query['sql'].lower()
                from_parts = sql.split(' from ')
                if len(from_parts) > 1:
                    table = from_parts[1].split()[0].strip().replace('`', '')
                    table_patterns[table] += 1
                    call_tables[table] += 1

        # 한 호출 내에서 같은 테이블에 대한 반복 접근 계산
        table_accesses_per_call.append(max(call_tables.values()) if call_tables else 0)

    # 특정 테이블에 대한 반복 쿼리가 많을 경우
    repeat_threshold = 5 * len(api_calls)  # 호출당 평균 5회 이상 반복
    repeat_tables = {table: count for table, count in table_patterns.items() if count >= repeat_threshold}

    if repeat_tables:
        n_plus_1_likelihood = "높음"
        n_plus_1_score += min(30, 5 * len(repeat_tables))  # 최대 30점

        table_list = ", ".join([f"{table} ({count}회)" for table, count in repeat_tables.items()])
        evidence.append(f"반복적인 테이블 접근: {table_list}")

    # 네 번째 N+1 지표: 유사한 패턴의 SELECT 쿼리 반복
    repeated_patterns_found = False
    for call in api_calls:
        select_patterns = defaultdict(int)
        for query in call['spy_queries']:
            if query['type'] == 'SELECT':
                # 쿼리에서 WHERE 절의 패턴 분석
                sql = query['sql'].lower()
                where_pattern = extract_where_pattern(sql)
                if where_pattern:
                    select_patterns[where_pattern] += 1

        # 특정 패턴의 쿼리가 여러 번 반복될 경우
        for pattern, count in select_patterns.items():
            if count > 3:  # 같은 패턴의 쿼리가 3회 이상 반복
                n_plus_1_likelihood = "높음"
                n_plus_1_score += min(20, count * 3)  # 최대 20점
                evidence.append(f"반복적 쿼리 패턴: 유사한 WHERE 조건 {count}회 반복")
                repeated_patterns_found = True
                break

        if repeated_patterns_found:
            break

    # N+1 점수 정규화 (최대 100)
    n_plus_1_score = min(100, n_plus_1_score)

    # 쿼리 복잡도 분석
    complexity_stats = analyze_query_complexity([call for call in api_calls if call['spy_queries']])

    return {
        'api_path': api_path,
        'calls_analyzed': len(api_calls),
        'n_plus_1_score': n_plus_1_score,
        'n_plus_1_likelihood': n_plus_1_likelihood,
        'avg_execution_time': avg_exec_time,
        'avg_query_count': {
            'hibernate': avg_hibernate_queries,
            'spy': avg_spy_queries,
            'ratio': avg_query_ratio
        },
        'avg_connections': avg_connections,
        'max_table_accesses': max(table_accesses_per_call) if table_accesses_per_call else 0,
        'repeated_tables': [{'table': table, 'count': count} for table, count in repeat_tables.items()],
        'query_complexity': complexity_stats,
        'evidence': evidence
    }


def extract_where_pattern(sql):
    """SQL 쿼리에서 WHERE 절 패턴 추출"""
    parts = sql.split(' where ')
    if len(parts) > 1:
        where_clause = parts[1].split(' order by ')[0].split(' group by ')[0]
        # 구체적인 값을 제거하고 패턴만 추출
        pattern = re.sub(r'[\'"][\w\s-]+[\'"]', '?', where_clause)
        pattern = re.sub(r'\d+', '?', pattern)
        return pattern
    return None


def analyze_query_complexity(api_calls):
    """쿼리 복잡도 분석"""
    total_complexity = 0
    complex_queries = []
    total_queries = 0
    join_queries = 0
    subquery_queries = 0

    for call in api_calls:
        for query in call['spy_queries']:
            if query['type'] == 'SELECT':
                total_queries += 1
                sql = query['sql'].lower()

                # 복잡도 계산
                complexity = 1

                # JOIN 복잡도
                joins = sql.count(' join ')
                if joins > 0:
                    complexity += joins
                    join_queries += 1

                # WHERE 절 복잡도
                where_conditions = 0
                if ' where ' in sql:
                    where_clause = sql.split(' where ')[1].split(' group by ')[0].split(' order by ')[0]
                    where_conditions = where_clause.count(' and ') + where_clause.count(' or ')
                    complexity += 0.5 * where_conditions

                # GROUP BY 복잡도
                if ' group by ' in sql:
                    complexity += 1

                # 서브쿼리 복잡도
                subqueries = sql.count('(select')
                if subqueries > 0:
                    complexity += 2 * subqueries
                    subquery_queries += 1

                # HAVING 복잡도
                if ' having ' in sql:
                    complexity += 1

                total_complexity += complexity

                # 복잡한 쿼리 저장
                if complexity > 3:
                    complex_queries.append({
                        'sql': query['sql'],
                        'complexity': complexity,
                        'execution_time': query['execution_time']
                    })

    # 결과 계산
    avg_complexity = total_complexity / total_queries if total_queries > 0 else 0
    join_percentage = (join_queries / total_queries) * 100 if total_queries > 0 else 0
    subquery_percentage = (subquery_queries / total_queries) * 100 if total_queries > 0 else 0

    # 복잡도가 높은 순으로 정렬
    complex_queries.sort(key=lambda q: q['complexity'], reverse=True)

    return {
        'avg_complexity': avg_complexity,
        'join_percentage': join_percentage,
        'subquery_percentage': subquery_percentage,
        'complex_queries': complex_queries[:3]  # 상위 3개만 반환
    }


def generate_summary_report(api_analysis_results):
    """여러 API 경로에 대한 종합 보고서 생성"""
    print("\n" + "="*80)
    print(f"             다중 API 경로 N+1 문제 분석 보고서")
    print("="*80)

    if not api_analysis_results:
        print("\n분석할 API 호출 정보가 없습니다.")
        return

    # 전체 요약
    print("\n1. 전체 요약")
    print("-"*80)

    print(f"분석된 API 경로 수: {len(api_analysis_results)}개")

    n_plus_1_apis = [api for api in api_analysis_results if api['n_plus_1_score'] > 50]
    print(f"N+1 문제 가능성이 높은 API 수: {len(n_plus_1_apis)}개")

    if n_plus_1_apis:
        print("\nN+1 문제가 가장 심각한 상위 API 경로:")
        for i, api in enumerate(n_plus_1_apis[:5]):  # 상위 5개만
            print(f"{i+1}. {api['api_path']} (점수: {api['n_plus_1_score']}/100)")

    # API별 상세 분석
    print("\n2. API별 상세 분석 (N+1 점수 기준 정렬)")
    print("-"*80)

    for i, api in enumerate(api_analysis_results):
        print(f"\n[{i+1}] {api['api_path']}")
        print(f"  • 분석 호출 수: {api['calls_analyzed']}회")
        print(f"  • N+1 문제 점수: {api['n_plus_1_score']}/100 ({api['n_plus_1_likelihood']})")
        print(f"  • 평균 실행 시간: {api['avg_execution_time']:.1f}ms")
        print(f"  • 평균 쿼리 수: Hibernate {api['avg_query_count']['hibernate']:.1f}개, P6Spy {api['avg_query_count']['spy']:.1f}개 (비율: {api['avg_query_count']['ratio']:.1f})")

        if api['evidence']:
            print("  • N+1 문제 증거:")
            for evidence in api['evidence']:
                print(f"    - {evidence}")

        if api['repeated_tables']:
            print("  • 반복적으로 접근하는 테이블:")
            for table_info in api['repeated_tables'][:3]:  # 상위 3개만
                print(f"    - {table_info['table']}: {table_info['count']}회")

    # 문제 해결 권장사항
    print("\n3. 문제 해결 권장사항")
    print("-"*80)

    recommendations = [
        "Fetch Join 적용: 관련 엔티티를 한 번에 로드하여 N+1 문제 해결",
        "@EntityGraph 활용: 복잡한 관계의 그래프를 정의하여 효율적으로 로딩",
        "Batch Size 설정: @BatchSize 어노테이션이나 hibernate.default_batch_fetch_size 설정으로 N+1 완화",
        "DTO 프로젝션: 필요한 필드만 선택적으로 조회하여 조인 최소화",
        "QueryDSL 등 활용: 동적 쿼리를 관리하기 쉽게 작성하여 N+1 회피",
        "LazyLoading 최적화: 불필요한 지연 로딩을 제거하고 필요한 곳만 적용"
    ]

    for i, rec in enumerate(recommendations):
        print(f"{i+1}. {rec}")

    # 결론
    print("\n4. 결론")
    print("-"*80)

    high_score_apis = [api for api in api_analysis_results if api['n_plus_1_score'] > 70]
    medium_score_apis = [api for api in api_analysis_results if 30 < api['n_plus_1_score'] <= 70]
    low_score_apis = [api for api in api_analysis_results if api['n_plus_1_score'] <= 30]

    print(f"N+1 문제 심각도 높음 ({len(high_score_apis)}개 API): 즉시 최적화 필요")
    print(f"N+1 문제 심각도 중간 ({len(medium_score_apis)}개 API): 검토 후 최적화 권장")
    print(f"N+1 문제 심각도 낮음 ({len(low_score_apis)}개 API): 현재 상태 양호")

    # JSON 파일로 결과 저장
    try:
        with open('api_n_plus_1_analysis.json', 'w', encoding='utf-8') as f:
            json.dump(api_analysis_results, f, ensure_ascii=False, indent=2)
        print("\n상세 분석 결과가 'api_n_plus_1_analysis.json' 파일로 저장되었습니다.")
    except Exception as e:
        print(f"\n결과 저장 중 오류 발생: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='여러 API 경로에 대한 N+1 문제 분석')
    parser.add_argument('--hibernate-log', default='logs/hibernate.log', help='Hibernate 로그 파일 경로')
    parser.add_argument('--spy-log', default='logs/spy.log', help='P6Spy 로그 파일 경로')
    parser.add_argument('--warmup', type=int, default=1, help='각 API별 워밍업 호출 수')
    parser.add_argument('--min-calls', type=int, default=2, help='분석할 최소 API 호출 수')
    parser.add_argument('--debug', action='store_true', help='디버깅 정보 출력')

    args = parser.parse_args()

    analyze_multiple_apis(
        hibernate_log_path=args.hibernate_log,
        spy_log_path=args.spy_log,
        warmup_count=args.warmup,
        min_calls_per_api=args.min_calls,
        debug=args.debug
    )
