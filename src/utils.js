export function selectFirstMatch(peerArray, preferences){
   for (const preference of preferences) {
      if (peerArray.includes(preference)) {
        return preference; // Return the first match
      }
    }
    return null; // Return null if no match is found
}

export function selectKeyExchange(keyShareEntries, preferences){
   const groups = keyShareEntries.map(e=>e.group);
   const selectedGroup = selectFirstMatch(groups, preferences);
   return keyShareEntries.filter((item) => {
      return item.group.name == selectedGroup.name
   })[0]
}