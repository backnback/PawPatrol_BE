import re
from collections import defaultdict
from datetime import datetime
import os
import argparse

def analyze_api_performance(hibernate_log_path='logs/hibernate.log',
                            spy_log_path='logs/spy.log',
                            target_api_path='api/v1/protections/my-cases',
                            warmup_count=2,
                            debug=False):
    """
    API 성능 분석을 수행하고 보고서 형식으로 결과를 출력합니다.

    Args:
        hibernate_log_path (str): Hibernate 로그 파일 경로
        spy_log_path (str): P6Spy 로그 파일 경로
        target_api_path (str): 분석할 API 경로
        warmup_count (int): 워밍업 호출로 간주할 초기 호출 횟수
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

    # API 경로 정규화 (Git Bash 경로 변환 문제 해결)
    if target_api_path.startswith('/'):
        search_paths = [
            target_api_path,  # 원래 경로
            target_api_path.lstrip('/'),  # 슬래시 제거
        ]
    else:
        search_paths = [
            target_api_path,  # 원래 경로
            '/' + target_api_path,  # 슬래시 추가
        ]

    if debug:
        print(f"검색할 API 경로: {search_paths}")

    # API 호출 정보 추출 (여러 가능한 경로 패턴 시도)
    api_calls = []
    for path in search_paths:
        calls = extract_api_calls(hibernate_lines, path, debug)
        if calls:
            api_calls = calls
            print(f"API 경로 '{path}'에 대한 호출 {len(calls)}개를 찾았습니다.")
            break

    if not api_calls:
        print(f"어떤 API 경로에서도 호출을 찾을 수 없습니다. 다음 경로를 시도했습니다: {search_paths}")
        return

    # P6Spy 로그 분석
    connection_queries = extract_spy_queries(spy_lines, debug)

    # API 호출과 쿼리 매칭
    match_queries_to_api_calls(api_calls, connection_queries, debug)

    # 워밍업 호출과 분석 호출 분리
    if len(api_calls) <= warmup_count:
        print(f"경고: 총 {len(api_calls)}개의 API 호출을 발견했습니다. 이는 워밍업 호출 수({warmup_count})보다 적거나 같습니다.")
        print("정확한 분석을 위해서는 더 많은 API 호출이 필요합니다.")
        warmup_calls = api_calls
        analysis_calls = []
    else:
        warmup_calls = api_calls[:warmup_count]
        analysis_calls = api_calls[warmup_count:]

    # 결과 보고서 생성
    generate_performance_report(warmup_calls, analysis_calls, target_api_path, warmup_count)

def extract_api_calls(hibernate_lines, target_api_path, debug):
    """Hibernate 로그에서 API 호출 정보 추출"""
    api_calls = []
    api_calls_found = 0

    # 다양한 API 호출 패턴 지원
    api_patterns = [
        f"API 호출 시작: GET {target_api_path}",
        f"========== API 호출 시작: GET {target_api_path} ==========",
        f"API 호출 시작: GET {target_api_path.lstrip('/')}",
        f"========== API 호출 시작: GET {target_api_path.lstrip('/')} ==========",
    ]

    completion_patterns = [
        f"API 호출 완료: GET {target_api_path}",
        f"========== API 호출 완료: GET {target_api_path} ==========",
        f"API 호출 완료: GET {target_api_path.lstrip('/')}",
        f"========== API 호출 완료: GET {target_api_path.lstrip('/')} ==========",
    ]

    for i, line in enumerate(hibernate_lines):
        is_start = False
        for pattern in api_patterns:
            if pattern in line:
                is_start = True
                break

        if is_start:
            api_calls_found += 1
            start_line_idx = i

            # 시작 시간 추출
            start_time = extract_timestamp(line, hibernate_lines, i, 5)

            # 종료 로그 검색
            end_found = False
            for j in range(i+1, min(i+100, len(hibernate_lines))):
                is_completion = False
                for pattern in completion_patterns:
                    if pattern in hibernate_lines[j]:
                        is_completion = True
                        break

                if is_completion:
                    end_found = True
                    end_line_idx = j
                    end_line = hibernate_lines[j]

                    # 종료 시간 추출
                    end_time = extract_timestamp(end_line, hibernate_lines, j, 5)

                    # 실행 시간 추출
                    execution_time = None
                    exec_match = re.search(r'실행시간: (\d+)ms', end_line)
                    if exec_match:
                        execution_time = int(exec_match.group(1))

                    # SQL 쿼리 추출
                    queries = []
                    for k in range(i+1, j):
                        if "org.hibernate.SQL" in hibernate_lines[k] and "Message:" in hibernate_lines[k]:
                            sql_match = re.search(r'Message: (.+)', hibernate_lines[k])
                            if sql_match:
                                sql = sql_match.group(1).strip()
                                sql_type = sql.split()[0].upper() if sql else "UNKNOWN"
                                queries.append({
                                    'sql': sql,
                                    'type': sql_type
                                })

                    if start_time and end_time and execution_time is not None:
                        api_calls.append({
                            'start_time': start_time,
                            'end_time': end_time,
                            'execution_time': execution_time,
                            'hibernate_queries': queries,
                            'spy_queries': []
                        })

                        if debug:
                            print(f"API 호출 #{api_calls_found} 발견: {start_time} ~ {end_time}, 쿼리 수: {len(queries)}")
                    break

    if debug:
        print(f"총 {api_calls_found}개 API 호출 중 {len(api_calls)}개 정보 추출 완료")

    return api_calls

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

        if debug:
            print(f"API 호출 #{i+1}: {len(api_call['spy_queries'])}개 쿼리 매칭됨")
            for conn_id, count in conn_matches.items():
                print(f"  - 연결 ID {conn_id}: {count}개")

def generate_performance_report(warmup_calls, analysis_calls, api_path, warmup_count):
    """성능 분석 보고서 생성"""
    all_calls = warmup_calls + analysis_calls

    if not all_calls:
        print("분석할 API 호출 정보가 없습니다.")
        return

    print("\n" + "="*80)
    print(f"             API 성능 분석 보고서: {api_path}")
    print("="*80)

    # 워밍업 호출 요약 출력
    print(f"\n워밍업 호출 ({warmup_count}회):")
    for i, call in enumerate(warmup_calls):
        print(f"  호출 #{i+1}: {call['execution_time']}ms, Hibernate 쿼리: {len(call['hibernate_queries'])}, P6Spy 쿼리: {len(call['spy_queries'])}")

    if not analysis_calls:
        print("\n분석 호출이 없습니다. 더 많은 API 호출 데이터가 필요합니다.")
        return

    # 분석 호출에 대한 요약 통계
    total_exec_time = sum(call['execution_time'] for call in analysis_calls)
    avg_exec_time = total_exec_time / len(analysis_calls)
    min_exec_time = min(call['execution_time'] for call in analysis_calls)
    max_exec_time = max(call['execution_time'] for call in analysis_calls)

    total_hibernate_queries = sum(len(call['hibernate_queries']) for call in analysis_calls)
    avg_hibernate_queries = total_hibernate_queries / len(analysis_calls)

    total_spy_queries = sum(len(call['spy_queries']) for call in analysis_calls)
    avg_spy_queries = total_spy_queries / len(analysis_calls)

    total_sql_time = sum(sum(q['execution_time'] for q in call['spy_queries']) for call in analysis_calls)
    sql_time_pct = (total_sql_time / total_exec_time) * 100 if total_exec_time > 0 else 0

    print("\n1. 요약 (워밍업 호출 제외)")
    print("-"*80)
    summary_data = [
        ["분석 대상 API", api_path],
        ["분석 횟수", f"{len(analysis_calls)}회 (워밍업 {warmup_count}회 제외)"],
        ["평균 응답 시간", f"{avg_exec_time:.1f}ms (최소: {min_exec_time}ms, 최대: {max_exec_time}ms)"],
        ["평균 SQL 쿼리 수", f"Hibernate: {avg_hibernate_queries:.1f}, P6Spy: {avg_spy_queries:.1f}"],
        ["SQL 쿼리 시간 비율", f"{sql_time_pct:.1f}% (API 총 시간 중)"]
    ]

    for item in summary_data:
        print(f"{item[0]:20}: {item[1]}")

    # 워밍업 호출과 비교
    if warmup_calls:
        warmup_avg_exec_time = sum(call['execution_time'] for call in warmup_calls) / len(warmup_calls)
        warmup_avg_hibernate = sum(len(call['hibernate_queries']) for call in warmup_calls) / len(warmup_calls)
        warmup_avg_spy = sum(len(call['spy_queries']) for call in warmup_calls) / len(warmup_calls)

        exec_time_change = ((avg_exec_time - warmup_avg_exec_time) / warmup_avg_exec_time) * 100 if warmup_avg_exec_time > 0 else 0
        print(f"\n워밍업 대비 성능 변화: {'-' if exec_time_change < 0 else '+'}{abs(exec_time_change):.1f}% (실행 시간)")
        print(f"워밍업 평균 쿼리 수: Hibernate: {warmup_avg_hibernate:.1f}, P6Spy: {warmup_avg_spy:.1f}")

    # 개별 호출 분석
    print("\n2. API 호출 세부 분석 (워밍업 제외)")
    print("-"*80)

    for i, call in enumerate(analysis_calls):
        spy_queries = call['spy_queries']
        hibernate_queries = call['hibernate_queries']

        total_query_time = sum(q['execution_time'] for q in spy_queries)
        query_time_pct = (total_query_time / call['execution_time']) * 100 if call['execution_time'] > 0 else 0

        # 이전 호출과 비교 (두 번째 이상 호출부터)
        change_indicators = ""
        if i > 0:
            prev_call = analysis_calls[i-1]

            # 실행 시간 변화
            exec_change = ((call['execution_time'] - prev_call['execution_time']) / prev_call['execution_time']) * 100 if prev_call['execution_time'] > 0 else 0
            exec_arrow = "↓" if exec_change < 0 else "↑"

            # 쿼리 시간 변화
            prev_total_query_time = sum(q['execution_time'] for q in prev_call['spy_queries'])
            query_change = ((total_query_time - prev_total_query_time) / prev_total_query_time) * 100 if prev_total_query_time > 0 else 0
            query_arrow = "↓" if query_change < 0 else "↑"

            # 쿼리 수 변화
            query_count_change = ((len(spy_queries) - len(prev_call['spy_queries'])) / len(prev_call['spy_queries'])) * 100 if prev_call['spy_queries'] else 0
            count_arrow = "↓" if query_count_change < 0 else "↑"

            change_indicators = f" ({exec_arrow} {abs(exec_change):.1f}%, 쿼리 시간: {query_arrow} {abs(query_change):.1f}%, 쿼리 수: {count_arrow} {abs(query_count_change):.1f}%)"

        print(f"\n호출 #{i+warmup_count+1} ({call['start_time']})")
        call_data = [
            ["총 실행 시간", f"{call['execution_time']}ms{change_indicators}"],
            ["SQL 쿼리 시간", f"{total_query_time}ms ({query_time_pct:.1f}%)"],
            ["SQL 쿼리 수", f"Hibernate: {len(hibernate_queries)}, P6Spy: {len(spy_queries)}"]
        ]

        for item in call_data:
            print(f"{item[0]:20}: {item[1]}")

        # 쿼리 유형 분석
        h_types = defaultdict(int)
        for q in hibernate_queries:
            h_types[q.get('type', 'UNKNOWN')] += 1

        s_types = defaultdict(int)
        for q in spy_queries:
            s_types[q.get('type', 'UNKNOWN')] += 1

        print("\n  쿼리 유형 분석:")
        query_types = []
        for qtype in sorted(set(list(h_types.keys()) + list(s_types.keys()))):
            query_types.append([qtype, h_types.get(qtype, 0), s_types.get(qtype, 0)])

        headers = ["쿼리 유형", "Hibernate", "P6Spy"]
        print(f"  {headers[0]:10} | {headers[1]:10} | {headers[2]:10}")
        print(f"  {'-'*10} | {'-'*10} | {'-'*10}")
        for row in query_types:
            print(f"  {row[0]:10} | {row[1]:10} | {row[2]:10}")

        # 가장 오래 걸린 쿼리
        slow_queries = [q for q in spy_queries if q['execution_time'] > 0]
        if slow_queries:
            slowest_query = max(slow_queries, key=lambda q: q['execution_time'])
            print(f"\n  가장 오래 걸린 쿼리 ({slowest_query['execution_time']}ms):")
            truncated_sql = slowest_query['sql']
            if len(truncated_sql) > 80:
                truncated_sql = truncated_sql[:80] + "..."
            print(f"  {truncated_sql}")

        # 연결 분석
        conn_usage = defaultdict(int)
        for q in spy_queries:
            conn_usage[q.get('conn_id', 'unknown')] += 1

        if len(conn_usage) > 1:
            print("\n  데이터베이스 연결 사용 분석:")
            print(f"  {'연결 ID':10} | {'쿼리 수':10}")
            print(f"  {'-'*10} | {'-'*10}")
            for conn_id, count in conn_usage.items():
                print(f"  {conn_id:10} | {count:10}")

    # JPA N+1 문제 분석
    print("\n3. JPA N+1 문제 분석")
    print("-"*80)

    n_plus_1_likelihood = "낮음"
    evidence = []

    # 첫 번째 N+1 지표: Hibernate와 P6Spy 쿼리 수 차이
    avg_query_ratio = avg_spy_queries / avg_hibernate_queries if avg_hibernate_queries > 0 else 0
    if avg_query_ratio > 2.0:
        n_plus_1_likelihood = "높음"
        evidence.append(f"P6Spy/Hibernate 쿼리 비율: {avg_query_ratio:.1f} (> 2.0)")

    # 두 번째 N+1 지표: 다수의 데이터베이스 연결 사용
    total_connections = set()
    for call in analysis_calls:
        call_connections = set(q.get('conn_id', 'unknown') for q in call['spy_queries'])
        if len(call_connections) > 2:  # 하나의 API 호출에 2개 이상의 연결 사용
            n_plus_1_likelihood = "높음"
            evidence.append(f"다중 연결 사용: {len(call_connections)}개의 연결")
        total_connections.update(call_connections)

    # 세 번째 N+1 지표: 특정 테이블에 대한 반복적인 SELECT 쿼리
    table_patterns = defaultdict(int)
    for call in analysis_calls:
        for query in call['spy_queries']:
            if query['type'] == 'SELECT':
                # 간단한 테이블 추출 (FROM 절 다음의 첫 단어)
                sql = query['sql'].lower()
                from_parts = sql.split(' from ')
                if len(from_parts) > 1:
                    table = from_parts[1].split()[0].strip().replace('`', '')
                    table_patterns[table] += 1

    # 특정 테이블에 대한 반복 쿼리가 많을 경우
    repeat_threshold = 5 * len(analysis_calls)  # 호출당 평균 5회 이상 반복
    repeat_tables = {table: count for table, count in table_patterns.items() if count >= repeat_threshold}
    if repeat_tables:
        n_plus_1_likelihood = "높음"
        table_list = ", ".join([f"{table} ({count}회)" for table, count in repeat_tables.items()])
        evidence.append(f"반복적인 테이블 접근: {table_list}")

    # 네 번째 N+1 지표: 유사한 패턴의 SELECT 쿼리 반복
    for call in analysis_calls:
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
                evidence.append(f"반복적 쿼리 패턴: 유사한 WHERE 조건 {count}회 반복")
                break

    print(f"N+1 문제 가능성: {n_plus_1_likelihood}")
    if evidence:
        print("\n발견된 N+1 문제 증거:")
        for e in evidence:
            print(f"- {e}")

    # 반복적으로 접근하는 테이블 분석
    print("\n테이블별 접근 빈도:")
    print(f"{'테이블':20} | {'접근 횟수':10}")
    print(f"{'-'*20} | {'-'*10}")
    for table, count in sorted(table_patterns.items(), key=lambda x: x[1], reverse=True)[:10]:  # 상위 10개만
        print(f"{table:20} | {count:10}")

    # 최적화 권장사항
    print("\n4. 최적화 권장사항")
    print("-"*80)

    recommendations = [
        "Fetch Join 적용: 주요 엔티티 조회 시 연관 엔티티를 함께 로드하여 후속 쿼리 감소",
        "@EntityGraph 활용: 특정 API에 필요한 그래프 기반 데이터 로딩 구성",
        "Batch Size 설정: `@BatchSize` 또는 `default_batch_fetch_size` 설정으로 N+1 완화",
        "DTO 프로젝션: 필요한 데이터만 선택적으로 조회하여 불필요한 쿼리 제거"
    ]

    for i, rec in enumerate(recommendations):
        print(f"{i+1}. {rec}")

    # 쿼리 복잡도 분석
    print("\n5. 쿼리 복잡도 분석")
    print("-"*80)

    complexity_stats = analyze_query_complexity(analysis_calls)
    print(f"평균 쿼리 복잡도: {complexity_stats['avg_complexity']:.1f}")
    print(f"JOIN 사용 쿼리 비율: {complexity_stats['join_percentage']:.1f}%")
    print(f"서브쿼리 사용 비율: {complexity_stats['subquery_percentage']:.1f}%")

    if complexity_stats['complex_queries']:
        print("\n복잡한 쿼리 목록:")
        for i, query in enumerate(complexity_stats['complex_queries'][:3]):  # 상위 3개만
            print(f"{i+1}. 복잡도: {query['complexity']}, 실행시간: {query['execution_time']}ms")
            truncated_sql = query['sql']
            if len(truncated_sql) > 100:
                truncated_sql = truncated_sql[:100] + "..."
            print(f"   {truncated_sql}")

    # 결론
    print("\n6. 결론")
    print("-"*80)

    # 워밍업 후 성능 안정화 분석
    if len(analysis_calls) > 1:
        first_call = analysis_calls[0]
        last_call = analysis_calls[-1]
        exec_change = ((last_call['execution_time'] - first_call['execution_time']) / first_call['execution_time']) * 100 if first_call['execution_time'] > 0 else 0

        if abs(exec_change) < 10:
            print("워밍업 후 API 성능이 안정적으로 유지되었습니다.")
        elif exec_change < 0:
            print(f"워밍업 후에도 API 성능이 계속 향상되었습니다: {abs(exec_change):.1f}% 개선")
        else:
            print(f"워밍업 후 API 성능이 점차 저하되었습니다: {exec_change:.1f}% 악화")

    # 히든 쿼리의 중요성
    query_diff_pct = ((avg_spy_queries - avg_hibernate_queries) / avg_hibernate_queries) * 100 if avg_hibernate_queries > 0 else 0
    print(f"\nP6Spy는 Hibernate가 기록한 것보다 평균 {query_diff_pct:.1f}% 더 많은 쿼리를 감지했습니다.")
    print("이는 Hibernate 로그만으로는 파악할 수 없는 추가적인 데이터베이스 상호작용이 있음을 나타냅니다.")

    if n_plus_1_likelihood == "높음":
        print("\n해당 API는 N+1 쿼리 문제의 징후를 보이고 있으며, 추가 최적화가 권장됩니다.")
    else:
        print("\n해당 API는 심각한 N+1 쿼리 문제를 보이지 않으나, 성능 개선을 위한 추가 검토를 권장합니다.")

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
        'complex_queries': complex_queries
    }

if __name__ == "__main__":
    # 명령줄 인수를 받는 대신 하드코딩된 기본값 사용
    analyze_api_performance()
